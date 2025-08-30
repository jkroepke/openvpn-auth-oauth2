package cache

import (
	"sync"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-plugin/client"
)

type Cache struct {
	data map[uint64]cacheEntry
	mu   sync.RWMutex
}

type cacheEntry struct {
	client    *client.Client
	timestamp time.Time
}

func New() *Cache {
	c := &Cache{
		data: make(map[uint64]cacheEntry),
	}

	go func() {
		// Periodically clean up expired entries
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			c.cleanup()
		}
	}()

	return c
}

func (c *Cache) Get(key uint64) (*client.Client, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.data[key]
	if !exists {
		return nil, false
	}

	return entry.client, true
}

func (c *Cache) Set(key uint64, client *client.Client) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data[key] = cacheEntry{
		client:    client,
		timestamp: time.Now(),
	}
}

func (c *Cache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.data {
		if now.Sub(entry.timestamp) > 10*time.Minute {
			delete(c.data, key)
		}
	}
}
