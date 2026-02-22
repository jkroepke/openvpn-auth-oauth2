package tokenstorage

import (
	"context"
	"time"
)

// Storage defines the interface for token storage implementations.
// All methods accept a context for cancellation and timeout support.
type Storage interface {
	// Get retrieves a token for the given client identifier.
	// Returns ErrNotExists if the token does not exist or has expired.
	Get(ctx context.Context, client string) (string, error)

	// Set stores a token for the given client identifier.
	Set(ctx context.Context, client string, token string) error

	// Delete removes a token for the given client identifier.
	Delete(ctx context.Context, client string) error

	// Close releases any resources held by the storage.
	Close() error
}

type item struct {
	Expires time.Time
	Data    []byte
}

type DataMap map[string]item
