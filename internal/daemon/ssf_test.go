//nolint:testpackage // Tests exercise the unexported SSF receiver setup.
package daemon

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/ssf"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/ssf/ssftest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type eventRecorder struct {
	events []ssf.Event
	mu     sync.Mutex
}

func (r *eventRecorder) HandleEvent(_ context.Context, event ssf.Event) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, event)

	return 1, nil
}

func (r *eventRecorder) handled() []ssf.Event {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]ssf.Event(nil), r.events...)
}

func ssfConfig(t *testing.T, transmitter *ssftest.Transmitter) *config.Config {
	t.Helper()

	issuer, err := types.NewURL(transmitter.Issuer())
	require.NoError(t, err)

	conf := config.Defaults
	conf.SSF.Enabled = true
	conf.SSF.Issuer = issuer
	conf.SSF.Poll.Token = types.Secret(transmitter.Token())
	conf.SSF.Poll.Interval = 10 * time.Millisecond

	return &conf
}

func TestSetupSSFReceiver(t *testing.T) {
	t.Parallel()

	transmitter := ssftest.New(t, ssftest.WithIssuerPath("/realms/vpn"))
	recorder := &eventRecorder{}

	receiver, err := setupSSFReceiver(t.Context(), slog.New(slog.DiscardHandler), ssfConfig(t, transmitter), transmitter.Client(), recorder, nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)

	go func() { done <- receiver.Run(ctx) }()

	jti := transmitter.EmitSessionRevoked(t, ssftest.IssSub("https://idp.example.com", "user-1"))

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		assert.Contains(collect, transmitter.Acked(), jti)
	}, 5*time.Second, 10*time.Millisecond)

	cancel()
	require.NoError(t, <-done)

	events := recorder.handled()
	require.Len(t, events, 1)
	assert.Equal(t, ssf.Subject{Issuer: "https://idp.example.com", Subject: "user-1"}, events[0].Subject)
}

func TestSetupSSFReceiverDiscoveryError(t *testing.T) {
	t.Parallel()

	transmitter := ssftest.New(t)
	conf := ssfConfig(t, transmitter)
	conf.SSF.Poll.Token = "wrong"

	_, err := setupSSFReceiver(t.Context(), slog.New(slog.DiscardHandler), conf, transmitter.Client(), &eventRecorder{}, nil)
	require.ErrorContains(t, err, "discover SSF transmitter")
	require.ErrorContains(t, err, "401")
}

// failingTransport fails the first failures requests, like a transmitter
// that is unreachable for a moment.
type failingTransport struct {
	next     http.RoundTripper
	failures int
	mu       sync.Mutex
}

func (f *failingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	failing := f.failures > 0
	f.failures--
	f.mu.Unlock()

	if failing {
		return nil, errors.New("connection refused")
	}

	return f.next.RoundTrip(req)
}

func TestSSFReceiverService(t *testing.T) {
	t.Parallel()

	t.Run("first start fails on discovery errors", func(t *testing.T) {
		t.Parallel()

		transmitter := ssftest.New(t)
		client := *transmitter.Client()
		client.Transport = &failingTransport{next: client.Transport, failures: 1}

		_, err := ssfReceiverService(t.Context(), slog.New(slog.DiscardHandler), ssfConfig(t, transmitter), &client, &eventRecorder{}, nil, false)
		require.ErrorContains(t, err, "connection refused")
	})

	t.Run("reload retries discovery", func(t *testing.T) {
		t.Parallel()

		transmitter := ssftest.New(t)
		client := *transmitter.Client()
		client.Transport = &failingTransport{next: client.Transport, failures: 3}
		recorder := &eventRecorder{}

		run, err := ssfReceiverService(t.Context(), slog.New(slog.DiscardHandler), ssfConfig(t, transmitter), &client, recorder, nil, true)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)

		go func() { done <- run(ctx) }()

		jti := transmitter.EmitSessionRevoked(t, ssftest.IssSub("https://idp.example.com", "user-1"))

		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			assert.Contains(collect, transmitter.Acked(), jti)
		}, 5*time.Second, 10*time.Millisecond)

		cancel()
		require.NoError(t, <-done)
		assert.Len(t, recorder.handled(), 1)
	})
}
