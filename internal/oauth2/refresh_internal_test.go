package oauth2

import (
	"context"
	"log/slog"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/openvpn/connection"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
)

func TestRefreshClientAuthInternalTokenRestoresClientConfigNames(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	conf := config.Defaults
	conf.OAuth2.Refresh.Enabled = true
	conf.OAuth2.Refresh.ValidateUser = false

	storage := newInMemoryStorage(t)
	internalToken, err := encodeInternalRefreshToken(internalRefreshToken{Username: "alice", ClientConfigNames: []string{"profile", "base"}})
	require.NoError(t, err)
	require.NoError(t, storage.Set(ctx, "7", internalToken))

	client := Client{conf: &conf, storage: storage}
	result, ok, err := client.RefreshClientAuth(ctx, slog.New(slog.DiscardHandler), connection.Client{CID: 7})

	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, types.UserInfo{Username: "alice"}, result.User)
	require.Nil(t, result.Tokens)
	require.Equal(t, []string{"profile", "base"}, result.ClientConfigNames)
}

func TestRefreshClientAuthInternalTokenKeepsLegacyEmptyToken(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	conf := config.Defaults
	conf.OAuth2.Refresh.Enabled = true
	conf.OAuth2.Refresh.ValidateUser = false

	storage := newInMemoryStorage(t)
	require.NoError(t, storage.Set(ctx, "7", types.EmptyToken))

	client := Client{conf: &conf, storage: storage}
	result, ok, err := client.RefreshClientAuth(ctx, slog.New(slog.DiscardHandler), connection.Client{CID: 7})

	require.NoError(t, err)
	require.True(t, ok)
	require.Nil(t, result.Tokens)
	require.Nil(t, result.ClientConfigNames)
}

func TestRefreshClientAuthInternalTokenKeepsLegacyClientConfigToken(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	conf := config.Defaults
	conf.OAuth2.Refresh.Enabled = true
	conf.OAuth2.Refresh.ValidateUser = false

	storage := newInMemoryStorage(t)
	require.NoError(t, storage.Set(
		ctx,
		"7",
		internalRefreshTokenPrefix+`{"client-config-names":["profile","base"]}`,
	))

	client := Client{conf: &conf, storage: storage}
	result, ok, err := client.RefreshClientAuth(
		ctx,
		slog.New(slog.DiscardHandler),
		connection.Client{CID: 7},
	)

	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, types.UserInfo{}, result.User)
	require.Nil(t, result.Tokens)
	require.Equal(t, []string{"profile", "base"}, result.ClientConfigNames)
}

func TestRefreshClientAuthInternalTokenWithoutUsernameFallsBackToInteractiveAuthentication(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	conf := config.Defaults
	conf.OAuth2.Refresh.Enabled = true
	conf.OAuth2.Refresh.ValidateUser = false
	conf.OpenVPN.EnforceUniqueUser = true

	storage := newInMemoryStorage(t)
	require.NoError(t, storage.Set(
		ctx,
		"7",
		internalRefreshTokenPrefix+`{"client-config-names":["profile","base"]}`,
	))

	client := Client{conf: &conf, storage: storage}
	result, ok, err := client.RefreshClientAuth(
		ctx,
		slog.New(slog.DiscardHandler),
		connection.Client{CID: 7},
	)

	require.NoError(t, err)
	require.False(t, ok)
	require.Equal(t, types.RefreshResult{}, result)
}

func TestRefreshedUserInfoMissingIDTokenClaimsReturnsError(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	conf.OAuth2.UserInfo = true

	client := Client{conf: &conf}
	userInfo, err := client.refreshedUserInfo(t.Context(), &idtoken.IDToken{})

	require.ErrorIs(t, err, rp.ErrMissingIDToken)
	require.Nil(t, userInfo)
}

func TestProviderRefreshTokenStoresClientConfigNames(t *testing.T) {
	t.Parallel()

	token := providerRefreshToken{RefreshToken: "provider-refresh-token", ClientConfigNames: []string{"selected"}}

	encoded, err := encodeProviderRefreshToken(token)
	require.NoError(t, err)

	decoded, err := decodeProviderRefreshToken(encoded)
	require.NoError(t, err)
	require.Equal(t, token, decoded)
}

func TestProviderRefreshTokenKeepsLegacyRawToken(t *testing.T) {
	t.Parallel()

	token, err := decodeProviderRefreshToken("provider-refresh-token")
	require.NoError(t, err)
	require.Equal(t, providerRefreshToken{RefreshToken: "provider-refresh-token"}, token)
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

			token, err := decodeInternalRefreshToken(testCase.refreshToken)

			require.Error(t, err)
			require.Contains(t, err.Error(), testCase.expectedErr)
			require.Equal(t, internalRefreshToken{}, token)
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

			token, err := decodeProviderRefreshToken(testCase.refreshToken)

			require.Error(t, err)
			require.Contains(t, err.Error(), testCase.expectedErr)
			require.Equal(t, providerRefreshToken{}, token)
		})
	}
}

func TestEncodeInternalRefreshToken(t *testing.T) {
	t.Parallel()

	emptyToken, err := encodeInternalRefreshToken(internalRefreshToken{})
	require.NoError(t, err)
	require.Equal(t, types.EmptyToken, emptyToken)

	encodedToken, err := encodeInternalRefreshToken(internalRefreshToken{Username: "alice", ClientConfigNames: []string{"profile"}})
	require.NoError(t, err)
	require.Contains(t, encodedToken, internalRefreshTokenPrefix)
	require.Contains(t, encodedToken, `"username":"alice"`)
}

func TestDecodeProviderRefreshTokenPreservesValidationError(t *testing.T) {
	t.Parallel()

	_, err := decodeProviderRefreshToken(providerRefreshTokenPrefix + `{"refresh-token":"provider-refresh-token","client-config-names":[""]}`)

	require.ErrorIs(t, err, types.ErrInvalidClaimType)
}
