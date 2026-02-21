package tokenstorage

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zitadel/oidc/v3/pkg/crypto"
)

var ErrNilData = errors.New("data map cannot be nil")

const (
	// DefaultGCInterval is the default interval for garbage collection.
	DefaultGCInterval = time.Minute
)

// InMemory provides an in-memory implementation of a token storage system.
// It stores encrypted tokens associated with clients, supports expiration,
// automatic garbage collection, and is safe for concurrent use.
type InMemory struct {
	data          DataMap      // holds the actual token data mapped by client identifier.
	encryptionKey string       // used to encrypt and decrypt token data.
	mu            sync.RWMutex // read-write mutex to ensure safe concurrent access.
	expires       time.Duration

	// Metrics
	hits             atomic.Uint64
	misses           atomic.Uint64
	expirations      atomic.Uint64
	encryptionErrors atomic.Uint64

	// GC control
	gcInterval time.Duration
	gcStop     chan struct{}
	gcWg       sync.WaitGroup
}

// NewInMemory creates a new in-memory token storage with the given encryption key and expiration duration.
// It starts a background goroutine for garbage collection of expired tokens.
func NewInMemory(encryptionKey string, expires time.Duration) *InMemory {
	return NewInMemoryWithGC(encryptionKey, expires, DefaultGCInterval)
}

// NewInMemoryWithGC creates a new in-memory token storage with custom GC interval.
// If gcInterval is 0 or negative, garbage collection is disabled.
func NewInMemoryWithGC(encryptionKey string, expires, gcInterval time.Duration) *InMemory {
	storage := &InMemory{
		data:          DataMap{},
		encryptionKey: encryptionKey,
		expires:       expires,
		gcInterval:    gcInterval,
		gcStop:        make(chan struct{}),
	}

	if gcInterval > 0 {
		storage.startGC()
	}

	return storage
}

// SetStorage replaces the current storage data with the provided DataMap.
// This is mainly used for testing or restoring state.
func (s *InMemory) SetStorage(data DataMap) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if data == nil {
		return ErrNilData
	}

	s.data = data

	return nil
}

// Set stores an encrypted token for a given client, with an expiration time.
// The token is encrypted using AES before storage.
func (s *InMemory) Set(_ context.Context, client, token string) error {
	encryptedBytes, err := crypto.EncryptBytesAES([]byte(token), s.encryptionKey)
	if err != nil {
		s.encryptionErrors.Add(1)

		return fmt.Errorf("encrypt error: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.data[client] = item{
		Data:    encryptedBytes,
		Expires: time.Now().Add(s.expires),
	}

	return nil
}

// Get retrieves and decrypts the token for a given client.
// If the token is expired or does not exist, ErrNotExists is returned.
func (s *InMemory) Get(_ context.Context, client string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, ok := s.data[client]
	if !ok {
		s.misses.Add(1)

		return "", ErrNotExists
	}

	if data.Expires.Before(time.Now()) {
		delete(s.data, client)
		s.expirations.Add(1)
		s.misses.Add(1)

		return "", ErrNotExists
	}

	// we need to copy the data, since crypto.DecryptBytesAES will modify the slice in place
	encryptedBytes := make([]byte, len(data.Data))
	copy(encryptedBytes, data.Data)

	token, err := crypto.DecryptBytesAES(encryptedBytes, s.encryptionKey)
	if err != nil {
		s.encryptionErrors.Add(1)

		return "", fmt.Errorf("decrypt error: %w", err)
	}

	s.hits.Add(1)

	return string(token), nil
}

// Delete removes the token data for a given client from storage.
func (s *InMemory) Delete(_ context.Context, client string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.data, client)

	return nil
}

// Close stops the garbage collection goroutine and releases resources.
func (s *InMemory) Close() error {
	close(s.gcStop)
	s.gcWg.Wait()

	return nil
}

// Stats returns current storage statistics.
func (s *InMemory) Stats() StorageStats {
	s.mu.RLock()
	size := len(s.data)
	s.mu.RUnlock()

	return StorageStats{
		Size:             size,
		Hits:             s.hits.Load(),
		Misses:           s.misses.Load(),
		Expirations:      s.expirations.Load(),
		EncryptionErrors: s.encryptionErrors.Load(),
	}
}

// startGC starts the background garbage collection goroutine.
func (s *InMemory) startGC() {
	s.gcWg.Go(func() {
		ticker := time.NewTicker(s.gcInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s.collectExpired()
			case <-s.gcStop:
				return
			}
		}
	})
}

// collectExpired removes all expired tokens from storage.
func (s *InMemory) collectExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for client, item := range s.data {
		if item.Expires.Before(now) {
			delete(s.data, client)
			s.expirations.Add(1)
		}
	}
}
