package tokenstorage

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/zitadel/oidc/v3/pkg/crypto"
)

type InMemory struct {
	data          DataMap
	encryptionKey string
	mu            sync.RWMutex
	expires       time.Duration
}

func NewInMemory(encryptionKey string, expires time.Duration) *InMemory {
	storage := &InMemory{
		data:          DataMap{},
		encryptionKey: encryptionKey,
		expires:       expires,
		mu:            sync.RWMutex{},
	}

	return storage
}

func (s *InMemory) SetStorage(data DataMap) {
	s.mu.Lock()

	s.data = data

	s.mu.Unlock()
}

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

	encryptedBytes := make([]byte, len(data.Data))

	// we need to copy the data, since crypto.DecryptBytesAES will modify the slice in place
	copy(encryptedBytes, data.Data)

	token, err := crypto.DecryptBytesAES(encryptedBytes, s.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("decrypt error: %w", err)
	}

	return string(token), nil
}

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

func (s *InMemory) Close() error {
	return nil
}
