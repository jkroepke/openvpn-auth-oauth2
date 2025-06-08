package tokenstorage

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/zitadel/oidc/v3/pkg/crypto"
)

// InMemory provides an in-memory implementation of a token storage system.
// It stores encrypted tokens associated with clients, supports expiration, and is safe for concurrent use.
type InMemory struct {
	data DataMap // holds the actual token data mapped by client identifier.

	encryptionKey string        // used to encrypt and decrypt token data.
	mu            sync.RWMutex  // read-write mutex to ensure safe concurrent access.
	expires       time.Duration // defines the duration after which a token is considered expired.
}

// NewInMemory creates a new in-memory token storage with the given encryption key and expiration duration.
func NewInMemory(encryptionKey string, expires time.Duration) *InMemory {
	storage := &InMemory{
		data:          DataMap{},
		encryptionKey: encryptionKey,
		expires:       expires,
		mu:            sync.RWMutex{},
	}

	return storage
}

// SetStorage replaces the current storage data with the provided DataMap.
// This is mainly used for testing or restoring state.
func (s *InMemory) SetStorage(data DataMap) {
	s.mu.Lock()

	s.data = data

	s.mu.Unlock()
}

// Set stores an encrypted token for a given client, with an expiration time.
// The token is encrypted using AES before storage.
func (s *InMemory) Set(client, token string) error {
	s.mu.Lock()

	encryptedBytes, err := crypto.EncryptBytesAES([]byte(token), s.encryptionKey)
	if err != nil {
		s.mu.Unlock()

		return fmt.Errorf("decrypt error: %w", err)
	}

	s.data[client] = item{
		Data:    encryptedBytes,
		Expires: time.Now().Add(s.expires),
	}

	s.mu.Unlock()

	return nil
}

// Get retrieves and decrypts the token for a given client.
// If the token is expired or does not exist, an error is returned.
func (s *InMemory) Get(client string) (string, error) {
	s.mu.RLock()
	if s.data == nil {
		s.mu.RUnlock()

		return "", ErrNotExists
	}

	data, ok := s.data[client]
	if !ok {
		s.mu.RUnlock()

		return "", ErrNotExists
	}

	s.mu.RUnlock()

	if data.Expires.Before(time.Now()) {
		delErr := s.Delete(client)

		return "", errors.Join(ErrNotExists, delErr)
	}

	// we need to copy the data, since crypto.DecryptBytesAES will modify the slice in place
	encryptedBytes := make([]byte, len(data.Data))
	copy(encryptedBytes, data.Data)

	token, err := crypto.DecryptBytesAES(encryptedBytes, s.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("decrypt error: %w", err)
	}

	return string(token), nil
}

// Delete removes the token data for a given client from storage.
// If the storage is empty or the client does not exist, it does nothing.
func (s *InMemory) Delete(client string) error {
	s.mu.Lock()

	if s.data == nil {
		s.mu.Unlock()

		return nil
	}

	delete(s.data, client)

	s.mu.Unlock()

	return nil
}

// Close is a no-op for in-memory storage, but implements the interface for compatibility.
func (s *InMemory) Close() error {
	return nil
}
