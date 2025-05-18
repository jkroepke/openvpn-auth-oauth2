package tokenstorage

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zitadel/oidc/v3/pkg/crypto"
)

type InMemory struct {
	data          sync.Map
	encryptionKey string
	expires       time.Duration
}

type item struct {
	expires time.Time
	token   []byte
}

func NewInMemory(ctx context.Context, encryptionKey string, expires time.Duration) *InMemory {
	storage := &InMemory{
		data:          sync.Map{},
		encryptionKey: encryptionKey,
		expires:       expires,
	}
	go storage.collect(ctx)

	return storage
}

func (s *InMemory) Set(client, token string) error {
	encryptedBytes, err := crypto.EncryptBytesAES([]byte(token), s.encryptionKey)
	if err != nil {
		return fmt.Errorf("decrypt error: %w", err)
	}

	s.data.Store(client, item{token: encryptedBytes, expires: time.Now().Add(s.expires)})

	return nil
}

func (s *InMemory) Get(client string) (string, error) {
	data, ok := s.data.Load(client)
	if !ok {
		return "", ErrNotExists
	}

	item, ok := data.(item)
	if !ok {
		s.Delete(client)

		return "", ErrNotExists
	}

	encryptedBytes := make([]byte, len(item.token))

	// we need to copy the data, since crypto.DecryptBytesAES will modify the slice in place
	copy(encryptedBytes, item.token)

	token, err := crypto.DecryptBytesAES(encryptedBytes, s.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("decrypt error: %w", err)
	}

	return string(token), nil
}

func (s *InMemory) Delete(client string) {
	s.data.Delete(client)
}

func (s *InMemory) collect(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute * 5):
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
}
