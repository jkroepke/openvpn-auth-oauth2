//nolint:testpackage // Tests exercise the unexported SSF receiver setup.
package daemon

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/ssf"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/ssf/ssftest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	xoauth2 "golang.org/x/oauth2"
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

	conf := ssfConfig(t, transmitter)

	receiver, err := setupSSFReceiver(t.Context(), slog.New(slog.DiscardHandler), conf, transmitter.Client(), ssfTokenSource(t.Context(), conf, nil), recorder, nil)
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

	_, err := setupSSFReceiver(t.Context(), slog.New(slog.DiscardHandler), conf, transmitter.Client(), ssfTokenSource(t.Context(), conf, nil), &eventRecorder{}, nil)
	require.ErrorContains(t, err, "discover SSF transmitter")
	require.ErrorContains(t, err, "401")
}

type credentialsRecorder struct {
	scopes []string
	calls  int
}

func (r *credentialsRecorder) ClientCredentialsToken(_ context.Context, scopes ...string) (*xoauth2.Token, error) {
	r.calls++
	r.scopes = scopes

	return &xoauth2.Token{AccessToken: "client-credentials", Expiry: time.Now().Add(time.Hour)}, nil
}

func TestSSFTokenSource(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	conf.SSF.Poll.Token = "static"

	token, err := ssfTokenSource(t.Context(), &conf, nil).Token()
	require.NoError(t, err)
	assert.Equal(t, "static", token.AccessToken)

	recorder := &credentialsRecorder{}
	tokens := xoauth2.ReuseTokenSource(nil, clientCredentialsTokenSource{ctx: t.Context(), client: recorder, scopes: config.Defaults.SSF.Poll.Scopes})

	for range 3 {
		token, err = tokens.Token()
		require.NoError(t, err)
		assert.Equal(t, "client-credentials", token.AccessToken)
	}

	assert.Equal(t, 1, recorder.calls, "a token is reused until it expires")
	assert.Equal(t, []string{"ssf.read"}, recorder.scopes)
}
