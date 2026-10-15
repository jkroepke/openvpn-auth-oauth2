package ssf

import (
	"context"
	"errors"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// tokenExpiryDelta is how long before its expiry a cached token is renewed.
const tokenExpiryDelta = 10 * time.Second

// TokenSource provides the bearer token for the transmitter.
type TokenSource interface {
	// Token returns an access token. ctx bounds a token request.
	Token(ctx context.Context) (*oauth2.Token, error)
	// Invalidate drops a cached token, because the transmitter rejected it.
	Invalidate()
}

// StaticToken returns a TokenSource that always returns token.
func StaticToken(token string) TokenSource {
	return staticToken{token: &oauth2.Token{AccessToken: token}}
}

type staticToken struct {
	token *oauth2.Token
}

func (s staticToken) Token(context.Context) (*oauth2.Token, error) {
	return s.token, nil
}

func (staticToken) Invalidate() {}

// TokenFunc requests a new access token.
type TokenFunc func(ctx context.Context) (*oauth2.Token, error)

// CachedTokenSource returns a TokenSource that reuses the token from fetch
// until shortly before it expires, or until it is invalidated. A token
// without an expiry is reused until it is invalidated.
func CachedTokenSource(fetch TokenFunc) TokenSource {
	return &cachedTokenSource{fetch: fetch}
}

type cachedTokenSource struct {
	fetch TokenFunc
	token *oauth2.Token
	mu    sync.Mutex
}

func (c *cachedTokenSource) Token(ctx context.Context) (*oauth2.Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != nil && (c.token.Expiry.IsZero() || time.Until(c.token.Expiry) > tokenExpiryDelta) {
		return c.token, nil
	}

	token, err := c.fetch(ctx)
	if err != nil {
		return nil, err
	}

	if token == nil || token.AccessToken == "" {
		return nil, errors.New("token response has no access token")
	}

	c.token = token

	return token, nil
}

func (c *cachedTokenSource) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.token = nil
}
