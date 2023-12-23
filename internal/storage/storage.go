package storage

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

type Storage struct {
	encryptionKey *rsa.PrivateKey

	expires time.Duration
	data    sync.Map
}

type item struct {
	token   []byte
	expires time.Time
}

func New(expires time.Duration) *Storage {
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	storage := &Storage{
		privkey,
		expires,
		sync.Map{},
	}
	go storage.collect()

	return storage
}

func (s *Storage) collect() {
	for {
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

		time.Sleep(time.Minute * 5)
	}
}

func (s *Storage) Set(client uint64, token string) error {
	encryptedToken, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &s.encryptionKey.PublicKey, []byte(token), nil)
	if err != nil {
		return fmt.Errorf("encrypt error: %w", err)
	}

	s.data.Store(client, item{encryptedToken, time.Now().Add(s.expires)})

	return nil
}

func (s *Storage) Get(client uint64) (string, error) {
	data, ok := s.data.Load(client)
	if !ok {
		return "", ErrNotExists
	}

	token, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, s.encryptionKey, data.(item).token, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt error: %w", err)
	}

	return string(token), nil
}

func (s *Storage) Delete(client uint64) {
	s.data.Delete(client)
}
