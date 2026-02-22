package tokenstorage

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/crypto"
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
	data    DataMap        // holds the actual token data mapped by client identifier.
	cipher  *crypto.Cipher // handles encryption and decryption operations.
	mu      sync.RWMutex   // read-write mutex to ensure safe concurrent access.
	expires time.Duration

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
		data:       DataMap{},
		cipher:     crypto.New(encryptionKey),
		expires:    expires,
		gcInterval: gcInterval,
		gcStop:     make(chan struct{}),
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
// The token is encrypted using Salsa20 before storage.
func (s *InMemory) Set(_ context.Context, client, token string) error {
	encryptedBytes, err := s.cipher.EncryptBytes([]byte(token))
	if err != nil {
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
	now := time.Now()

	s.mu.RLock()
	data, ok := s.data[client]
	s.mu.RUnlock()

	if !ok {
		return "", ErrNotExists
	}

	if data.Expires.Before(now) {
		s.mu.Lock()
		delete(s.data, client)
		s.mu.Unlock()

		return "", ErrNotExists
	}

	// we need to copy the data, since crypto.DecryptBytesAES will modify the slice in place
	encryptedBytes := make([]byte, len(data.Data))
	copy(encryptedBytes, data.Data)

	token, err := s.cipher.DecryptBytesBase64(encryptedBytes)
	if err != nil {
		return "", fmt.Errorf("decrypt error: %w", err)
	}

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
		}
	}
}
