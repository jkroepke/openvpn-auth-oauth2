package oauth2 //nolint:testpackage

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/tokenstorage"
	"github.com/stretchr/testify/require"
)

func TestStoreSelectedProfileRefreshState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := slog.New(slog.DiscardHandler)
	session := state.State{Client: state.ClientIdentifier{CID: 7}}

	t.Run("disabled refresh does not store token", func(t *testing.T) {
		t.Parallel()

		conf := config.Defaults
		conf.OAuth2.Refresh.Enabled = false
		storage := tokenstorage.NewInMemoryWithGC("1234567890123456", time.Hour, 0)
		client := Client{conf: &conf, storage: storage}

		client.storeSelectedProfileRefreshState(ctx, logger, session, "7", "selected")

		_, err := storage.Get(ctx, "7")
		require.ErrorIs(t, err, tokenstorage.ErrNotExists)
	})

	t.Run("internal refresh token stores selected profile", func(t *testing.T) {
		t.Parallel()

		conf := config.Defaults
		conf.OAuth2.Refresh.Enabled = true
		conf.OAuth2.Refresh.ValidateUser = false
		storage := tokenstorage.NewInMemoryWithGC("1234567890123456", time.Hour, 0)
		client := Client{conf: &conf, storage: storage}

		client.storeSelectedProfileRefreshState(ctx, logger, session, "7", "selected")

		refreshToken, err := storage.Get(ctx, "7")
		require.NoError(t, err)

		clientConfigNames, err := decodeInternalRefreshToken(refreshToken)
		require.NoError(t, err)
		require.Equal(t, []string{"selected"}, clientConfigNames)
	})

	t.Run("provider refresh token stores selected profile", func(t *testing.T) {
		t.Parallel()

		conf := config.Defaults
		conf.OAuth2.Refresh.Enabled = true
		conf.OAuth2.Refresh.ValidateUser = true
		storage := tokenstorage.NewInMemoryWithGC("1234567890123456", time.Hour, 0)
		storedToken, err := encodeProviderRefreshToken("provider-refresh-token", []string{"previous"})
		require.NoError(t, err)
		require.NoError(t, storage.Set(ctx, "7", storedToken))

		client := Client{conf: &conf, storage: storage}
		client.storeSelectedProfileRefreshState(ctx, logger, session, "7", "selected")

		refreshToken, err := storage.Get(ctx, "7")
		require.NoError(t, err)

		providerRefreshToken, clientConfigNames, err := decodeProviderRefreshToken(refreshToken)
		require.NoError(t, err)
		require.Equal(t, "provider-refresh-token", providerRefreshToken)
		require.Equal(t, []string{"selected"}, clientConfigNames)
	})

	t.Run("storage get failure does not store token", func(t *testing.T) {
		t.Parallel()

		conf := config.Defaults
		conf.OAuth2.Refresh.Enabled = true
		conf.OAuth2.Refresh.ValidateUser = true
		storage := &profileRefreshStorage{getErr: errors.New("get failed")}
		client := Client{conf: &conf, storage: storage}

		client.storeSelectedProfileRefreshState(ctx, logger, session, "7", "selected")

		require.False(t, storage.setCalled)
	})

	t.Run("malformed stored provider token is not overwritten", func(t *testing.T) {
		t.Parallel()

		conf := config.Defaults
		conf.OAuth2.Refresh.Enabled = true
		conf.OAuth2.Refresh.ValidateUser = true
		storage := tokenstorage.NewInMemoryWithGC("1234567890123456", time.Hour, 0)
		require.NoError(t, storage.Set(ctx, "7", providerRefreshTokenPrefix+"{"))

		client := Client{conf: &conf, storage: storage}
		client.storeSelectedProfileRefreshState(ctx, logger, session, "7", "selected")

		refreshToken, err := storage.Get(ctx, "7")
		require.NoError(t, err)
		require.Equal(t, providerRefreshTokenPrefix+"{", refreshToken)
	})

	t.Run("storage set failure is handled", func(t *testing.T) {
		t.Parallel()

		storedToken, err := encodeProviderRefreshToken("provider-refresh-token", []string{"previous"})
		require.NoError(t, err)

		conf := config.Defaults
		conf.OAuth2.Refresh.Enabled = true
		conf.OAuth2.Refresh.ValidateUser = true
		storage := &profileRefreshStorage{
			getToken: storedToken,
			setErr:   errors.New("set failed"),
		}
		client := Client{conf: &conf, storage: storage}

		client.storeSelectedProfileRefreshState(ctx, logger, session, "7", "selected")

		require.True(t, storage.setCalled)

		providerRefreshToken, clientConfigNames, err := decodeProviderRefreshToken(storage.setToken)
		require.NoError(t, err)
		require.Equal(t, "provider-refresh-token", providerRefreshToken)
		require.Equal(t, []string{"selected"}, clientConfigNames)
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
