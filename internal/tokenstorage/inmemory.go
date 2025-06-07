package tokenstorage

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zitadel/oidc/v3/pkg/crypto"
)

type InMemory struct {
	cancelFn      context.CancelFunc
	data          sync.Map
	encryptionKey string
	expires       time.Duration
}

type item struct {
	expires time.Time
	token   []byte
}

func NewInMemory(ctx context.Context, encryptionKey string, expires, cleanupInterval time.Duration) *InMemory {
	ctx, cancel := context.WithCancel(ctx)

	storage := &InMemory{
		cancelFn:      cancel,
		data:          sync.Map{},
		encryptionKey: encryptionKey,
		expires:       expires,
	}

	go storage.collect(ctx, time.NewTicker(cleanupInterval))

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

func (s *InMemory) Close() error {
	s.cancelFn()

	return nil
}

// collect periodically removes expired tokens from the in-memory store.
func (s *InMemory) collect(ctx context.Context, ticker *time.Ticker) {
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.data.Range(func(client, data any) bool {
				entry, ok := data.(item)
				if !ok {
					// Log instead of panic to avoid crashing the cleanup goroutine
					fmt.Printf("tokenstorage: unexpected type in data map: %T\n", data)
					s.data.Delete(client)
					return true
				}

				if entry.expires.Compare(time.Now()) == -1 {
					s.data.Delete(client)
				}

				return true
			})
		}
	}
}
