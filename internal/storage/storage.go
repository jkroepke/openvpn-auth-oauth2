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
	token   string
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

func (storage *Storage) collect() {
	for {
		storage.data.Range(func(client, data any) bool {
			entry, ok := data.(item)
			if !ok {
				panic(data)
			}

			if entry.expires.Compare(time.Now()) == -1 {
				storage.data.Delete(client)
			}

			return true
		})

		time.Sleep(time.Minute * 5)
	}
}

func (storage *Storage) Set(client uint64, token string) error {
	encryptedToken, err := crypto.EncryptAES(token, storage.encryptionKey)
	if err != nil {
		return fmt.Errorf("encrypt error: %w", err)
	}

	storage.data.Store(client, item{encryptedToken, time.Now().Add(storage.expires)})

	return nil
}

func (storage *Storage) Get(client uint64) (string, error) {
	data, ok := storage.data.Load(client)
	if !ok {
		return "", ErrNotExists
	}

	token, err := crypto.DecryptAES(data.(item).token, storage.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("decrypt error: %w", err)
	}

	return token, nil
}

func (storage *Storage) Delete(client uint64) {
	storage.data.Delete(client)
}
