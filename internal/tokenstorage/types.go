package tokenstorage

import (
	"context"
	"time"
)

type Storage interface {
	Get(client string) (string, error)
	Close() error
	Delete(client string) error
	Set(client string, token string) error
}

// MultiServerStorage extends Storage to support multiple OpenVPN servers
type MultiServerStorage interface {
	Storage
	GetForServer(client, serverName string) (string, error)
	SetForServer(client, serverName, token string) error
	DeleteForServer(client, serverName string) error
	CleanupExpiredTokens(ctx context.Context, interval time.Duration)
}

type item struct {
	Expires time.Time
	Data    []byte
}

type DataMap map[string]item
