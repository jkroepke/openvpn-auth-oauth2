package tokenstorage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
	"github.com/zitadel/oidc/v3/pkg/crypto"
)

// SQLite provides a SQLite-based implementation of a token storage system.
// It stores encrypted tokens associated with clients and servers, supports expiration, and is safe for concurrent use.
type SQLite struct {
	db            *sql.DB
	encryptionKey string
	expires       time.Duration
	mu            sync.RWMutex
}

// NewSQLite creates a new SQLite token storage
func NewSQLite(dbPath, encryptionKey string, expires time.Duration) (*SQLite, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %w", err)
	}

	storage := &SQLite{
		db:            db,
		encryptionKey: encryptionKey,
		expires:       expires,
		mu:            sync.RWMutex{},
	}

	if err := storage.initDB(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	return storage, nil
}

func (s *SQLite) initDB() error {
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		client_id TEXT NOT NULL,
		server_name TEXT NOT NULL,
		encrypted_token BLOB NOT NULL,
		expires_at DATETIME NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(client_id, server_name)
	);
	
	CREATE INDEX IF NOT EXISTS idx_tokens_client_server ON tokens(client_id, server_name);
	CREATE INDEX IF NOT EXISTS idx_tokens_expires ON tokens(expires_at);
	`

	_, err := s.db.Exec(createTableSQL)
	return err
}

// Set stores an encrypted token for a given client with default server name.
func (s *SQLite) Set(client, token string) error {
	return s.SetForServer(client, "default", token)
}

// SetForServer stores an encrypted token for a given client and server.
func (s *SQLite) SetForServer(client, serverName, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	encryptedBytes, err := crypto.EncryptBytesAES([]byte(token), s.encryptionKey)
	if err != nil {
		return fmt.Errorf("encrypt error: %w", err)
	}

	expiresAt := time.Now().Add(s.expires)

	query := `
	INSERT OR REPLACE INTO tokens (client_id, server_name, encrypted_token, expires_at, updated_at)
	VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
	`

	_, err = s.db.Exec(query, client, serverName, encryptedBytes, expiresAt)
	if err != nil {
		return fmt.Errorf("failed to store token: %w", err)
	}

	return nil
}

// Get retrieves and decrypts the token for a given client with default server name.
func (s *SQLite) Get(client string) (string, error) {
	return s.GetForServer(client, "default")
}

// GetForServer retrieves and decrypts the token for a given client and server.
func (s *SQLite) GetForServer(client, serverName string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	query := `
	SELECT encrypted_token, expires_at FROM tokens 
	WHERE client_id = ? AND server_name = ? AND expires_at > CURRENT_TIMESTAMP
	`

	var encryptedBytes []byte
	var expiresAt time.Time

	err := s.db.QueryRow(query, client, serverName).Scan(&encryptedBytes, &expiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotExists
		}
		return "", fmt.Errorf("failed to retrieve token: %w", err)
	}

	// Copy the data since crypto.DecryptBytesAES modifies the slice in place
	encryptedBytesCopy := make([]byte, len(encryptedBytes))
	copy(encryptedBytesCopy, encryptedBytes)

	token, err := crypto.DecryptBytesAES(encryptedBytesCopy, s.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("decrypt error: %w", err)
	}

	return string(token), nil
}

// Delete removes the token data for a given client with default server name.
func (s *SQLite) Delete(client string) error {
	return s.DeleteForServer(client, "default")
}

// DeleteForServer removes the token data for a given client and server.
func (s *SQLite) DeleteForServer(client, serverName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `DELETE FROM tokens WHERE client_id = ? AND server_name = ?`
	_, err := s.db.Exec(query, client, serverName)
	if err != nil {
		return fmt.Errorf("failed to delete token: %w", err)
	}

	return nil
}

// DeleteExpired removes all expired tokens from the database.
func (s *SQLite) DeleteExpired() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := `DELETE FROM tokens WHERE expires_at <= CURRENT_TIMESTAMP`
	_, err := s.db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to delete expired tokens: %w", err)
	}

	return nil
}

// Close closes the database connection.
func (s *SQLite) Close() error {
	return s.db.Close()
}

// CleanupExpiredTokens runs a background cleanup of expired tokens.
func (s *SQLite) CleanupExpiredTokens(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.DeleteExpired(); err != nil {
				// Log error but continue
				fmt.Printf("Failed to cleanup expired tokens: %v\n", err)
			}
		}
	}
}
