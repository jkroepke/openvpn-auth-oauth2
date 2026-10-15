package oauth2

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/openvpn/connection"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/sessionregistry"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
)

const testIssuer = "https://idp.example.com"

func newTestTokens(sid, email string) *idtoken.IDToken {
	claims := map[string]any{}
	if sid != "" {
		claims["sid"] = sid
	}

	return &idtoken.IDToken{
		IDTokenClaims: &idtoken.Claims{
			Issuer:  testIssuer,
			Subject: "alice-sub",
			EMail:   email,
			Claims:  claims,
		},
	}
}

func TestIdentityFromTokens(t *testing.T) {
	t.Parallel()

	user := types.UserInfo{Email: "userinfo@example.com"}

	for _, tc := range []struct {
		name     string
		tokens   *idtoken.IDToken
		expected sessionregistry.Identity
	}{
		{
			name:     "no tokens",
			expected: sessionregistry.Identity{Email: "userinfo@example.com"},
		},
		{
			name:     "no ID token",
			tokens:   &idtoken.IDToken{},
			expected: sessionregistry.Identity{Email: "userinfo@example.com"},
		},
		{
			name:   "all claims",
			tokens: newTestTokens("sid-1", "alice@example.com"),
			expected: sessionregistry.Identity{
				Issuer: testIssuer, Subject: "alice-sub", SessionID: "sid-1", Email: "alice@example.com",
			},
		},
		{
			name:     "email from UserInfo",
			tokens:   newTestTokens("", ""),
			expected: sessionregistry.Identity{Issuer: testIssuer, Subject: "alice-sub", Email: "userinfo@example.com"},
		},
		{
			name: "sid is not a string",
			tokens: &idtoken.IDToken{IDTokenClaims: &idtoken.Claims{
				Issuer:  testIssuer,
				Subject: "alice-sub",
				Claims:  map[string]any{"sid": 1},
			}},
			expected: sessionregistry.Identity{Issuer: testIssuer, Subject: "alice-sub", Email: "userinfo@example.com"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.expected, identityFromTokens(tc.tokens, user))
		})
	}
}

func TestRegisterClient(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	logger := slog.New(slog.DiscardHandler)
	identity := sessionregistry.Identity{Issuer: testIssuer, Subject: "alice-sub"}

	t.Run("records identity", func(t *testing.T) {
		t.Parallel()

		client := Client{sessions: sessionregistry.New()}
		client.RegisterClient(ctx, logger, state.ClientIdentifier{CID: 3, SessionID: "ovpn-1"}, "alice", identity)

		entries := client.sessions.Lookup(identity)
		require.Len(t, entries, 1)
		assert.Equal(t, uint64(3), entries[0].CID)
		assert.Equal(t, "ovpn-1", entries[0].OpenVPNSessionID)
		assert.Equal(t, "alice", entries[0].Username)
		assert.WithinDuration(t, time.Now(), entries[0].AuthenticatedAt, time.Minute)
	})

	t.Run("skips client without identity", func(t *testing.T) {
		t.Parallel()

		client := Client{sessions: sessionregistry.New()}
		client.RegisterClient(ctx, logger, state.ClientIdentifier{CID: 3}, "alice", sessionregistry.Identity{})

		assert.Equal(t, 0, client.sessions.Len())
	})

	t.Run("without registry", func(t *testing.T) {
		t.Parallel()

		conf := config.Defaults
		client := Client{conf: &conf}

		client.RegisterClient(ctx, logger, state.ClientIdentifier{CID: 3}, "alice", identity)
		client.ClientDisconnect(ctx, logger, connection.Client{CID: 3})
	})
}

func TestClientDisconnectRetainsSessionWithUseSessionID(t *testing.T) {
	t.Parallel()

	identity := sessionregistry.Identity{Issuer: testIssuer, Subject: "alice-sub"}

	for _, tc := range []struct {
		name         string
		refresh      bool
		useSessionID bool
		dormant      bool
	}{
		{name: "refresh disabled"},
		{name: "refresh by CID", refresh: true},
		{name: "refresh by session ID", refresh: true, useSessionID: true, dormant: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			conf := config.Defaults
			conf.OAuth2.Refresh.Enabled = tc.refresh
			conf.OAuth2.Refresh.ValidateUser = false
			conf.OAuth2.Refresh.UseSessionID = tc.useSessionID

			client := Client{conf: &conf, storage: newInMemoryStorage(t), sessions: sessionregistry.New()}
			client.RegisterClient(t.Context(), slog.New(slog.DiscardHandler), state.ClientIdentifier{CID: 3, SessionID: "ovpn-1"}, "alice", identity)
			client.ClientDisconnect(t.Context(), slog.New(slog.DiscardHandler), connection.Client{CID: 3, SessionID: "ovpn-1"})

			entries := client.sessions.Lookup(identity)
			if !tc.dormant {
				assert.Empty(t, entries)

				return
			}

			require.Len(t, entries, 1)
			assert.False(t, entries[0].Connected)
			assert.Equal(t, "ovpn-1", entries[0].OpenVPNSessionID)
		})
	}
}

func TestAcceptOAuth2ClientRegistersAndStoresIdentity(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	conf := config.Defaults
	conf.OAuth2.Refresh.Enabled = true
	conf.OAuth2.Refresh.ValidateUser = false

	storage := newInMemoryStorage(t)
	client := Client{conf: &conf, openvpn: &failingOpenVPNClient{}, storage: storage, sessions: sessionregistry.New()}

	client.acceptOAuth2Client(ctx, httptest.NewRecorder(), codeExchangeRequest{
		logger:   slog.New(slog.DiscardHandler),
		clientID: "1",
		session:  state.State{Client: state.ClientIdentifier{CID: 1, KID: 2}},
		tokens:   newTestTokens("sid-1", "alice@example.com"),
		username: "alice",
	}, "profile")

	identity := sessionregistry.Identity{Issuer: testIssuer, Subject: "alice-sub", SessionID: "sid-1", Email: "alice@example.com"}

	entries := client.sessions.Lookup(identity)
	require.Len(t, entries, 1)
	assert.Equal(t, uint64(1), entries[0].CID)

	refreshToken, err := storage.Get(ctx, "1")
	require.NoError(t, err)

	token, err := decodeInternalRefreshToken(refreshToken)
	require.NoError(t, err)
	assert.Equal(t, internalRefreshToken{Identity: identity, Username: "alice", ClientConfigNames: []string{"profile"}}, token)

	// A silent re-authentication restores the identity without a provider round trip.
	result, ok, err := client.RefreshClientAuth(ctx, slog.New(slog.DiscardHandler), connection.Client{CID: 1})
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, identity, result.Identity)
	assert.Equal(t, "alice", result.User.Username)
}

func TestAcceptOAuth2ClientDoesNotRegisterOnAcceptError(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	client := Client{
		conf:     &conf,
		openvpn:  &failingOpenVPNClient{acceptErr: context.Canceled},
		storage:  newInMemoryStorage(t),
		sessions: sessionregistry.New(),
	}

	client.acceptOAuth2Client(t.Context(), httptest.NewRecorder(), codeExchangeRequest{
		logger:  slog.New(slog.DiscardHandler),
		session: state.State{Client: state.ClientIdentifier{CID: 1, KID: 2}},
		tokens:  newTestTokens("", ""),
	})

	assert.Equal(t, 0, client.sessions.Len())
}

func TestRefreshClientAuthProviderTokenKeepsIdentity(t *testing.T) {
	t.Parallel()

	stored := sessionregistry.Identity{Issuer: testIssuer, Subject: "alice-sub", SessionID: "sid-1", Email: "alice@example.com"}

	for _, tc := range []struct {
		refreshed *idtoken.IDToken
		expected  sessionregistry.Identity
		name      string
	}{
		{
			name:      "refresh without ID token",
			refreshed: &idtoken.IDToken{},
			expected:  stored,
		},
		{
			name:      "refresh with new sid",
			refreshed: newTestTokens("sid-2", ""),
			expected:  sessionregistry.Identity{Issuer: testIssuer, Subject: "alice-sub", SessionID: "sid-2", Email: "alice@example.com"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := t.Context()
			conf := config.Defaults
			conf.OAuth2.Refresh.Enabled = true
			conf.OAuth2.Refresh.ValidateUser = true
			conf.OAuth2.Nonce = false
			conf.OAuth2.UserInfo = false
			conf.OAuth2.OpenVPNUsername = ""

			storage := newInMemoryStorage(t)
			storedToken, err := encodeProviderRefreshToken(providerRefreshToken{RefreshToken: "refresh-1", Identity: stored})
			require.NoError(t, err)
			require.NoError(t, storage.Set(ctx, "7", storedToken))

			client := Client{conf: &conf, storage: storage, provider: &refreshProvider{tokens: tc.refreshed}}

			result, ok, err := client.RefreshClientAuth(ctx, slog.New(slog.DiscardHandler), connection.Client{CID: 7, CommonName: "alice"})
			require.NoError(t, err)
			require.True(t, ok)
			assert.Equal(t, tc.expected, result.Identity)

			rotatedToken, err := storage.Get(ctx, "7")
			require.NoError(t, err)

			rotated, err := decodeProviderRefreshToken(rotatedToken)
			require.NoError(t, err)
			assert.Equal(t, providerRefreshToken{RefreshToken: "refresh-2", Identity: tc.expected}, rotated)
		})
	}
}

// refreshProvider is a [Provider] whose refresh returns a fixed token set.
type refreshProvider struct {
	tokens *idtoken.IDToken
}

func (p *refreshProvider) CheckUser(context.Context, state.State, types.UserInfo, *idtoken.IDToken) error {
	return nil
}

func (p *refreshProvider) GetProviderConfig() (types.ProviderConfig, error) {
	return types.ProviderConfig{}, nil
}

func (p *refreshProvider) GetName() string {
	return "refresh"
}

func (p *refreshProvider) GetRefreshToken(*idtoken.IDToken) (string, error) {
	return "refresh-2", nil
}

func (p *refreshProvider) GetUser(context.Context, *slog.Logger, *idtoken.IDToken, *types.UserInfo) (types.UserInfo, error) {
	return types.UserInfo{}, nil
}

func (p *refreshProvider) Refresh(context.Context, rp.RelyingParty, string) (*idtoken.IDToken, error) {
	return p.tokens, nil
}

func (p *refreshProvider) RevokeRefreshToken(context.Context, rp.RelyingParty, string) error {
	return nil
}
