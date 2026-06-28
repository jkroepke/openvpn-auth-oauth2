package google_test

import (
	"log/slog"
	"net/http"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/google"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestGetUser(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	provider, err := google.NewProvider(t.Context(), &conf, http.DefaultClient)
	require.NoError(t, err)

	user, err := provider.GetUser(
		t.Context(),
		slog.New(slog.DiscardHandler),
		&idtoken.IDToken{
			IDTokenClaims: &idtoken.Claims{
				TokenClaims: oidc.TokenClaims{Subject: "subject"},
				Claims: map[string]any{
					"preferred_username": "username",
				},
				PreferredUsername: "username",
				EMail:             "user@example.com",
			},
		},
		nil,
	)

	require.NoError(t, err)
	require.Equal(t, types.UserInfo{
		Subject:  "subject",
		Email:    "user@example.com",
		Username: "username",
	}, user)
}

func TestGetUserPrefersUserInfo(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	provider, err := google.NewProvider(t.Context(), &conf, http.DefaultClient)
	require.NoError(t, err)

	expectedUser := types.UserInfo{
		Subject:  "userinfo-subject",
		Email:    "userinfo@example.com",
		Username: "userinfo-user",
	}

	user, err := provider.GetUser(
		t.Context(),
		slog.New(slog.DiscardHandler),
		&idtoken.IDToken{},
		&expectedUser,
	)

	require.NoError(t, err)
	require.Equal(t, expectedUser, user)
}
