package oauth2 //nolint:testpackage

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/sessionregistry"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/tokenstorage"
	"github.com/stretchr/testify/require"
)

func TestStoreSelectedProfileRefreshState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := slog.New(slog.DiscardHandler)
	session := state.State{Client: state.ClientIdentifier{CID: 7}}
	identity := sessionregistry.Identity{Issuer: "https://idp.example.com", Subject: "alice-sub", SessionID: "sid-1"}
	selected := internalRefreshToken{Identity: identity, Username: "alice", ClientConfigNames: []string{"selected"}}

	t.Run("disabled refresh does not store token", func(t *testing.T) {
		t.Parallel()

		conf := config.Defaults
		conf.OAuth2.Refresh.Enabled = false
		storage := newInMemoryStorage(t)
		client := Client{conf: &conf, storage: storage}

		client.storeSelectedProfileRefreshState(ctx, logger, session, "7", selected)

		_, err := storage.Get(ctx, "7")
		require.ErrorIs(t, err, tokenstorage.ErrNotExists)
	})

	t.Run("internal refresh token stores selected profile", func(t *testing.T) {
		t.Parallel()

		conf := config.Defaults
		conf.OAuth2.Refresh.Enabled = true
		conf.OAuth2.Refresh.ValidateUser = false
		storage := newInMemoryStorage(t)
		client := Client{conf: &conf, storage: storage}

		client.storeSelectedProfileRefreshState(ctx, logger, session, "7", selected)

		refreshToken, err := storage.Get(ctx, "7")
		require.NoError(t, err)

		decoded, err := decodeInternalRefreshToken(refreshToken)
		require.NoError(t, err)
		require.Equal(t, selected, decoded)
	})

	t.Run("provider refresh token stores selected profile", func(t *testing.T) {
		t.Parallel()

		conf := config.Defaults
		conf.OAuth2.Refresh.Enabled = true
		conf.OAuth2.Refresh.ValidateUser = true
		storage := newInMemoryStorage(t)
		storedToken, err := encodeProviderRefreshToken(providerRefreshToken{
			RefreshToken:      "provider-refresh-token",
			ClientConfigNames: []string{"previous"},
			Identity:          sessionregistry.Identity{Email: "alice@example.com"},
		})
		require.NoError(t, err)
		require.NoError(t, storage.Set(ctx, "7", storedToken))

		client := Client{conf: &conf, storage: storage}
		client.storeSelectedProfileRefreshState(ctx, logger, session, "7", selected)

		refreshToken, err := storage.Get(ctx, "7")
		require.NoError(t, err)

		decoded, err := decodeProviderRefreshToken(refreshToken)
		require.NoError(t, err)
		require.Equal(t, providerRefreshToken{
			RefreshToken:      "provider-refresh-token",
			ClientConfigNames: []string{"selected"},
			Identity:          sessionregistry.Identity{Issuer: identity.Issuer, Subject: identity.Subject, SessionID: identity.SessionID, Email: "alice@example.com"},
		}, decoded)
	})

	t.Run("storage get failure does not store token", func(t *testing.T) {
		t.Parallel()

		conf := config.Defaults
		conf.OAuth2.Refresh.Enabled = true
		conf.OAuth2.Refresh.ValidateUser = true
		storage := &profileRefreshStorage{getErr: errors.New("get failed")}
		client := Client{conf: &conf, storage: storage}

		client.storeSelectedProfileRefreshState(ctx, logger, session, "7", selected)

		require.False(t, storage.setCalled)
	})

	t.Run("malformed stored provider token is not overwritten", func(t *testing.T) {
		t.Parallel()

		conf := config.Defaults
		conf.OAuth2.Refresh.Enabled = true
		conf.OAuth2.Refresh.ValidateUser = true
		storage := newInMemoryStorage(t)
		require.NoError(t, storage.Set(ctx, "7", providerRefreshTokenPrefix+"{"))

		client := Client{conf: &conf, storage: storage}
		client.storeSelectedProfileRefreshState(ctx, logger, session, "7", selected)

		refreshToken, err := storage.Get(ctx, "7")
		require.NoError(t, err)
		require.Equal(t, providerRefreshTokenPrefix+"{", refreshToken)
	})

	t.Run("storage set failure is handled", func(t *testing.T) {
		t.Parallel()

		storedToken, err := encodeProviderRefreshToken(providerRefreshToken{
			RefreshToken:      "provider-refresh-token",
			ClientConfigNames: []string{"previous"},
			Identity:          sessionregistry.Identity{Email: "alice@example.com"},
		})
		require.NoError(t, err)

		conf := config.Defaults
		conf.OAuth2.Refresh.Enabled = true
		conf.OAuth2.Refresh.ValidateUser = true
		storage := &profileRefreshStorage{
			getToken: storedToken,
			setErr:   errors.New("set failed"),
		}
		client := Client{conf: &conf, storage: storage}

		client.storeSelectedProfileRefreshState(ctx, logger, session, "7", selected)

		require.True(t, storage.setCalled)

		decoded, err := decodeProviderRefreshToken(storage.setToken)
		require.NoError(t, err)
		require.Equal(t, providerRefreshToken{
			RefreshToken:      "provider-refresh-token",
			ClientConfigNames: []string{"selected"},
			Identity:          sessionregistry.Identity{Issuer: identity.Issuer, Subject: identity.Subject, SessionID: identity.SessionID, Email: "alice@example.com"},
		}, decoded)
	})
}

type profileRefreshStorage struct {
	getToken  string
	getErr    error
	setToken  string
	setErr    error
	setCalled bool
}

func (s *profileRefreshStorage) Get(context.Context, string) (string, error) {
	if s.getErr != nil {
		return "", s.getErr
	}

	return s.getToken, nil
}

func (s *profileRefreshStorage) Consume(ctx context.Context, client string) (string, error) {
	token, err := s.Get(ctx, client)
	if err != nil {
		return "", err
	}

	s.getToken = ""

	return token, nil
}

func (s *profileRefreshStorage) Set(_ context.Context, _, token string) error {
	s.setCalled = true
	s.setToken = token

	return s.setErr
}

func (s *profileRefreshStorage) Delete(context.Context, string) error {
	return nil
}

func (s *profileRefreshStorage) Close() error {
	return nil
}
