package ssf_test

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/ssf"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/ssf/ssftest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// tokenCounter returns token and counts the requests.
type tokenCounter struct {
	token  oauth2.Token
	ctxErr error
	calls  int
	mu     sync.Mutex
}

func (c *tokenCounter) fetch(ctx context.Context) (*oauth2.Token, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.calls++
	c.ctxErr = ctx.Err()
	token := c.token

	return &token, nil
}

func (c *tokenCounter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.calls
}

func TestCachedTokenSource(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		expiry time.Time
		name   string
		calls  int
	}{
		{name: "valid", expiry: time.Now().Add(time.Hour), calls: 1},
		{name: "without expiry", calls: 1},
		{name: "about to expire", expiry: time.Now().Add(time.Second), calls: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			counter := &tokenCounter{token: oauth2.Token{AccessToken: "token", Expiry: tc.expiry}}
			tokens := ssf.CachedTokenSource(counter.fetch)

			for range 3 {
				token, err := tokens.Token(t.Context())
				require.NoError(t, err)
				assert.Equal(t, "token", token.AccessToken)
			}

			assert.Equal(t, tc.calls, counter.count())

			tokens.Invalidate()

			_, err := tokens.Token(t.Context())
			require.NoError(t, err)
			assert.Equal(t, tc.calls+1, counter.count(), "an invalidated token is requested again")
		})
	}
}

func TestCachedTokenSourceUsesRequestContext(t *testing.T) {
	t.Parallel()

	counter := &tokenCounter{token: oauth2.Token{AccessToken: "token"}}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := ssf.CachedTokenSource(counter.fetch).Token(ctx)
	require.NoError(t, err)
	require.ErrorIs(t, counter.ctxErr, context.Canceled)
}

func TestReceiverRenewsRejectedToken(t *testing.T) {
	t.Parallel()

	transmitter := ssftest.New(t)
	transmitter.FailNextPoll(http.StatusUnauthorized, nil)

	counter := &tokenCounter{token: oauth2.Token{AccessToken: transmitter.Token()}}
	receiver := ssf.NewReceiver(slog.New(slog.DiscardHandler), ssf.ReceiverConfig{
		Client:      transmitter.Client(),
		Verifier:    newVerifier(t, transmitter),
		Handler:     &handler{revoked: 1},
		Endpoint:    transmitter.PollEndpoint(),
		TokenSource: ssf.CachedTokenSource(counter.fetch),
		Interval:    testInterval,
		MaxEvents:   10,
	})

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)

	go func() { done <- receiver.Run(ctx) }()

	jti := transmitter.EmitSessionRevoked(t, revokedSubject())

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		assert.Contains(collect, transmitter.Acked(), jti)
	}, waitFor, tick)

	cancel()
	require.NoError(t, <-done)
	assert.Equal(t, 2, counter.count(), "the rejected token is requested again")
}
