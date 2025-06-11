package tokenstorage

import (
	"time"
)

type Storage interface {
	Get(client string) (string, error)
	Close() error
	Delete(client string) error
	Set(client string, token string) error
}

type item struct {
	Expires time.Time
	Data    []byte
}

type DataMap map[string]item
