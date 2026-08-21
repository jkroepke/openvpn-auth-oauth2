package generic_test

import (
	"log/slog"
	"net/http"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/types"
	"github.com/stretchr/testify/require"
)

func TestGetUser(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		conf     config.Config
		token    *idtoken.IDToken
		userInfo *types.UserInfo
		expected types.UserInfo
		err      error
	}{
		{
			name: "ID token identity",
			conf: config.Defaults,
			token: tokenWithClaims(
				map[string]any{},
				idtoken.Claims{
					Subject:           "subject",
					PreferredUsername: "username",
					EMail:             "user@example.com",
				},
			),
			expected: types.UserInfo{
				Subject:  "subject",
				Email:    "user@example.com",
				Username: "username",
			},
		},
		{
			name: "groups and roles",
			conf: config.Defaults,
			token: tokenWithClaims(
				map[string]any{
					"groups": []any{"group1", "group2"},
					"roles":  []string{"role1", "role2"},
				},
				idtoken.Claims{},
			),
			expected: types.UserInfo{
				Groups: []string{"group1", "group2"},
				Roles:  []string{"role1", "role2"},
			},
		},
		{
			name: "custom groups claim",
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.GroupsClaim = "groups_direct"

				return conf
			}(),
			token: tokenWithClaims(
				map[string]any{"groups_direct": []string{"group1", "group2"}},
				idtoken.Claims{},
			),
			expected: types.UserInfo{Groups: []string{"group1", "group2"}},
		},
		{
			name: "UserInfo takes precedence and token fills missing fields",
			conf: config.Defaults,
			token: tokenWithClaims(
				map[string]any{
					"groups": []string{"token-group"},
					"roles":  []string{"token-role"},
				},
				idtoken.Claims{
					Subject:           "token-subject",
					PreferredUsername: "token-username",
					EMail:             "token@example.com",
				},
			),
			userInfo: &types.UserInfo{
				Subject:  "userinfo-subject",
				Username: "userinfo-username",
				Groups:   []string{"userinfo-group"},
			},
			expected: types.UserInfo{
				Subject:  "userinfo-subject",
				Email:    "token@example.com",
				Username: "userinfo-username",
				Groups:   []string{"userinfo-group"},
				Roles:    []string{"token-role"},
			},
		},
		{
			name:  "UserInfo without ID token",
			conf:  config.Defaults,
			token: &idtoken.IDToken{},
			userInfo: &types.UserInfo{
				Subject:  "subject",
				Username: "username",
			},
			expected: types.UserInfo{
				Subject:  "subject",
				Username: "username",
			},
		},
		{
			name: "invalid groups element",
			conf: config.Defaults,
			token: tokenWithClaims(
				map[string]any{"groups": []any{"group1", 1}},
				idtoken.Claims{},
			),
			err: types.ErrInvalidClaimType,
		},
		{
			name: "invalid roles type",
			conf: config.Defaults,
			token: tokenWithClaims(
				map[string]any{"roles": "role1"},
				idtoken.Claims{},
			),
			err: types.ErrInvalidClaimType,
		},
		{
			name:     "missing token",
			conf:     config.Defaults,
			token:    nil,
			expected: types.UserInfo{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			provider, err := generic.NewProvider(t.Context(), &tc.conf, http.DefaultClient)
			require.NoError(t, err)

			userData, err := provider.GetUser(t.Context(), slog.New(slog.DiscardHandler), tc.token, tc.userInfo)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expected, userData)
		})
	}
}

func tokenWithClaims(rawClaims map[string]any, claims idtoken.Claims) *idtoken.IDToken {
	claims.Claims = rawClaims

	return &idtoken.IDToken{IDTokenClaims: &claims}
}
