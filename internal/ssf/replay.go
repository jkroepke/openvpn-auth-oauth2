package ssf

import (
	"sync"
	"time"
)

// replayCache remembers the jti of processed SETs until their iat is older
// than the maximum age, after which the iat check rejects them anyway.
type replayCache struct {
	expires map[string]time.Time
	mu      sync.Mutex
}

func newReplayCache() *replayCache {
	return &replayCache{expires: make(map[string]time.Time)}
}

// seen reports whether jti was added and has not expired at now.
func (c *replayCache) seen(jti string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	expires, ok := c.expires[jti]

	return ok && now.Before(expires)
}

// add remembers jti until expires and drops expired entries.
func (c *replayCache) add(jti string, expires, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for key, keyExpires := range c.expires {
		if !now.Before(keyExpires) {
			delete(c.expires, key)
		}
	}

	if now.Before(expires) {
		c.expires[jti] = expires
	}
}

func (c *replayCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return len(c.expires)
}
