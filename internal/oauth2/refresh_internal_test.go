package oauth2

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn/connection"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/tokenstorage"
	"github.com/stretchr/testify/require"
)

func TestRefreshClientAuthInternalTokenRestoresClientConfigNames(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	conf := config.Defaults
	conf.OAuth2.Refresh.Enabled = true
	conf.OAuth2.Refresh.ValidateUser = false

	storage := tokenstorage.NewInMemoryWithGC("1234567890123456", time.Hour, 0)
	internalToken, err := encodeInternalRefreshToken([]string{"profile", "base"})
	require.NoError(t, err)
	require.NoError(t, storage.Set(ctx, "7", internalToken))

	client := Client{conf: &conf, storage: storage}
	user, tokens, clientConfigNames, ok, err := client.RefreshClientAuth(ctx, slog.New(slog.DiscardHandler), connection.Client{CID: 7})

	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, types.UserInfo{}, user)
	require.Nil(t, tokens)
	require.Equal(t, []string{"profile", "base"}, clientConfigNames)
}

func TestRefreshClientAuthInternalTokenKeepsLegacyEmptyToken(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	conf := config.Defaults
	conf.OAuth2.Refresh.Enabled = true
	conf.OAuth2.Refresh.ValidateUser = false

	storage := tokenstorage.NewInMemoryWithGC("1234567890123456", time.Hour, 0)
	require.NoError(t, storage.Set(ctx, "7", types.EmptyToken))

	client := Client{conf: &conf, storage: storage}
	_, tokens, clientConfigNames, ok, err := client.RefreshClientAuth(ctx, slog.New(slog.DiscardHandler), connection.Client{CID: 7})

	require.NoError(t, err)
	require.True(t, ok)
	require.Nil(t, tokens)
	require.Nil(t, clientConfigNames)
}

func TestProviderRefreshTokenStoresClientConfigNames(t *testing.T) {
	t.Parallel()

	encoded, err := encodeProviderRefreshToken("provider-refresh-token", []string{"selected"})
	require.NoError(t, err)

	refreshToken, clientConfigNames, err := decodeProviderRefreshToken(encoded)
	require.NoError(t, err)
	require.Equal(t, "provider-refresh-token", refreshToken)
	require.Equal(t, []string{"selected"}, clientConfigNames)
}

func TestProviderRefreshTokenKeepsLegacyRawToken(t *testing.T) {
	t.Parallel()

	refreshToken, clientConfigNames, err := decodeProviderRefreshToken("provider-refresh-token")
	require.NoError(t, err)
	require.Equal(t, "provider-refresh-token", refreshToken)
	require.Nil(t, clientConfigNames)
}
