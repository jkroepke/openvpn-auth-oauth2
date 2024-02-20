package storage

import (
	"fmt"
	"sync"
	"time"

	"github.com/zitadel/oidc/v3/pkg/crypto"
)

type Storage struct {
	encryptionKey string

	expires time.Duration
	data    sync.Map
}

type item struct {
	token   []byte
	expires time.Time
}

func New(encryptionKey string, expires time.Duration) *Storage {
	storage := &Storage{
		encryptionKey,
		expires,
		sync.Map{},
	}
	go storage.collect()

	return storage
}

func (s *Storage) collect() {
	for {
		time.Sleep(time.Minute * 5)

		s.data.Range(func(client, data any) bool {
			entry, ok := data.(item)
			if !ok {
				panic(data)
			}

			if entry.expires.Compare(time.Now()) == -1 {
				s.data.Delete(client)
			}

			return true
		})
	}
}

func (s *Storage) Set(client string, token string) error {
	encryptedBytes, err := crypto.EncryptBytesAES([]byte(token), s.encryptionKey)
	if err != nil {
		return fmt.Errorf("decrypt error: %w", err)
	}

	s.data.Store(client, item{encryptedBytes, time.Now().Add(s.expires)})

	return nil
}

func (s *Storage) Get(client string) (string, error) {
	data, ok := s.data.Load(client)
	if !ok {
		return "", ErrNotExists
	}

	token, err := crypto.DecryptBytesAES(data.(item).token, s.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("decrypt error: %w", err)
	}

	return string(token), nil
}

func (s *Storage) Delete(client string) {
	s.data.Delete(client)
}
