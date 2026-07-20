package oauth2

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/openvpn/connection"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/tokenstorage"
	"github.com/stretchr/testify/require"
)

func TestRefreshClientAuthInternalTokenRestoresClientConfigNames(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	conf := config.Defaults
	conf.OAuth2.Refresh.Enabled = true
	conf.OAuth2.Refresh.ValidateUser = false

	storage := tokenstorage.NewInMemoryWithGC("1234567890123456", time.Hour, 0)
	internalToken, err := encodeInternalRefreshToken("alice", []string{"profile", "base"})
	require.NoError(t, err)
	require.NoError(t, storage.Set(ctx, "7", internalToken))

	client := Client{conf: &conf, storage: storage}
	user, tokens, clientConfigNames, ok, err := client.RefreshClientAuth(ctx, slog.New(slog.DiscardHandler), connection.Client{CID: 7})

	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, types.UserInfo{Username: "alice"}, user)
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

func TestRefreshClientAuthInternalTokenKeepsLegacyClientConfigToken(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	conf := config.Defaults
	conf.OAuth2.Refresh.Enabled = true
	conf.OAuth2.Refresh.ValidateUser = false

	storage := tokenstorage.NewInMemoryWithGC("1234567890123456", time.Hour, 0)
	require.NoError(t, storage.Set(
		ctx,
		"7",
		internalRefreshTokenPrefix+`{"client-config-names":["profile","base"]}`,
	))

	client := Client{conf: &conf, storage: storage}
	user, tokens, clientConfigNames, ok, err := client.RefreshClientAuth(
		ctx,
		slog.New(slog.DiscardHandler),
		connection.Client{CID: 7},
	)

	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, types.UserInfo{}, user)
	require.Nil(t, tokens)
	require.Equal(t, []string{"profile", "base"}, clientConfigNames)
}

func TestRefreshClientAuthInternalTokenWithoutUsernameFallsBackToInteractiveAuthentication(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	conf := config.Defaults
	conf.OAuth2.Refresh.Enabled = true
	conf.OAuth2.Refresh.ValidateUser = false
	conf.OpenVPN.EnforceUniqueUser = true

	storage := tokenstorage.NewInMemoryWithGC("1234567890123456", time.Hour, 0)
	require.NoError(t, storage.Set(
		ctx,
		"7",
		internalRefreshTokenPrefix+`{"client-config-names":["profile","base"]}`,
	))

	client := Client{conf: &conf, storage: storage}
	user, tokens, clientConfigNames, ok, err := client.RefreshClientAuth(
		ctx,
		slog.New(slog.DiscardHandler),
		connection.Client{CID: 7},
	)

	require.NoError(t, err)
	require.False(t, ok)
	require.Equal(t, types.UserInfo{}, user)
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

func TestDecodeInternalRefreshTokenErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		refreshToken string
		expectedErr  string
	}{
		{
			name:         "malformed json",
			refreshToken: internalRefreshTokenPrefix + `{`,
			expectedErr:  "unable to parse internal refresh token",
		},
		{
			name:         "empty client config name",
			refreshToken: internalRefreshTokenPrefix + `{"client-config-names":[""]}`,
			expectedErr:  "client config name is empty",
		},
		{
			name:         "invalid client config path",
			refreshToken: internalRefreshTokenPrefix + `{"client-config-names":["../default"]}`,
			expectedErr:  `invalid client config path "../default.conf"`,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			_, clientConfigNames, err := decodeInternalRefreshToken(testCase.refreshToken)

			require.Error(t, err)
			require.Contains(t, err.Error(), testCase.expectedErr)
			require.Nil(t, clientConfigNames)
		})
	}
}

func TestDecodeProviderRefreshTokenErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		refreshToken string
		expectedErr  string
	}{
		{
			name:         "malformed json",
			refreshToken: providerRefreshTokenPrefix + `{`,
			expectedErr:  "unable to parse provider refresh token",
		},
		{
			name:         "empty refresh token",
			refreshToken: providerRefreshTokenPrefix + `{"refresh-token":""}`,
			expectedErr:  "provider refresh token is empty",
		},
		{
			name:         "empty client config name",
			refreshToken: providerRefreshTokenPrefix + `{"refresh-token":"provider-refresh-token","client-config-names":[""]}`,
			expectedErr:  "client config name is empty",
		},
		{
			name:         "invalid client config path",
			refreshToken: providerRefreshTokenPrefix + `{"refresh-token":"provider-refresh-token","client-config-names":["../default"]}`,
			expectedErr:  `invalid client config path "../default.conf"`,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			refreshToken, clientConfigNames, err := decodeProviderRefreshToken(testCase.refreshToken)

			require.Error(t, err)
			require.Contains(t, err.Error(), testCase.expectedErr)
			require.Empty(t, refreshToken)
			require.Nil(t, clientConfigNames)
		})
	}
}

func TestEncodeInternalRefreshToken(t *testing.T) {
	t.Parallel()

	emptyToken, err := encodeInternalRefreshToken("", nil)
	require.NoError(t, err)
	require.Equal(t, types.EmptyToken, emptyToken)

	encodedToken, err := encodeInternalRefreshToken("alice", []string{"profile"})
	require.NoError(t, err)
	require.Contains(t, encodedToken, internalRefreshTokenPrefix)
	require.Contains(t, encodedToken, `"username":"alice"`)
}

func TestDecodeProviderRefreshTokenPreservesValidationError(t *testing.T) {
	t.Parallel()

	_, _, err := decodeProviderRefreshToken(providerRefreshTokenPrefix + `{"refresh-token":"provider-refresh-token","client-config-names":[""]}`)

	require.ErrorIs(t, err, types.ErrInvalidClaimType)
}
