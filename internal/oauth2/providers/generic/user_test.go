package generic_test

import (
	"errors"
	"log/slog"
	"net/http"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestGetUser(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		conf     config.Config
		token    idtoken.IDToken
		userInfo *types.UserInfo
		userData types.UserInfo
		err      error
	}{
		{
			"default token",
			config.Defaults,
			&oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					Claims: map[string]any{
						"preferred_username": "username",
					},
					TokenClaims: oidc.TokenClaims{
						Subject: "subject",
					},
				},
			},
			nil,
			types.UserInfo{
				Subject:  "subject",
				Username: "username",
			},
			nil,
		},
		{
			"default token with groups claim",
			func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Validate.Groups = []string{"group"}

				return conf
			}(),
			&oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					Claims: map[string]any{
						"preferred_username": "username",
						"groups":             []string{"group1", "group2"},
					},
					TokenClaims: oidc.TokenClaims{
						Subject: "subject",
					},
				},
			},
			nil,
			types.UserInfo{
				Subject:  "subject",
				Username: "username",
				Groups:   []string{"group1", "group2"},
			},
			nil,
		},
		{
			"default token with groups claim type any",
			func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Validate.Groups = []string{"group"}

				return conf
			}(),
			&oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					TokenClaims: oidc.TokenClaims{
						Subject: "subject",
					},
					Claims: map[string]any{
						"preferred_username": "username",
						"groups":             []any{any("group1"), any("group2")},
					},
				},
			},
			nil,
			types.UserInfo{
				Subject:  "subject",
				Username: "username",
				Groups:   []string{"group1", "group2"},
			},
			nil,
		},
		{
			"default token with invalid groups claim type any",
			func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Validate.Groups = []string{"group"}

				return conf
			}(),
			&oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					TokenClaims: oidc.TokenClaims{
						Subject: "subject",
					},
					Claims: map[string]any{
						"preferred_username": "username",
						"groups":             []any{any("group1"), any(0)},
					},
				},
			},
			nil,
			types.UserInfo{},
			types.ErrInvalidClaimType,
		},
		{
			"default token with custom groups claim",
			func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Validate.Groups = []string{"group"}

				return conf
			}(),
			&oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					TokenClaims: oidc.TokenClaims{
						Subject: "subject",
					},
					Claims: map[string]any{
						"preferred_username": "username",
						"groups_direct":      []string{"group1", "group2"},
					},
				},
			},
			nil,
			types.UserInfo{
				Subject:  "subject",
				Username: "username",
			},
			nil,
		},
		{
			"default token with configured custom groups claim",
			func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Validate.Groups = []string{"group"}
				conf.OAuth2.GroupsClaim = "groups_direct"

				return conf
			}(),
			&oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					TokenClaims: oidc.TokenClaims{
						Subject: "subject",
					},
					Claims: map[string]any{
						"preferred_username": "username",
						"groups_direct":      []string{"group1", "group2"},
					},
				},
			},
			nil,
			types.UserInfo{
				Subject:  "subject",
				Username: "username",
				Groups:   []string{"group1", "group2"},
			},
			nil,
		},
		{
			"default token with invalid groups claim",
			func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Validate.Groups = []string{"group"}

				return conf
			}(),
			&oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					TokenClaims: oidc.TokenClaims{
						Subject: "subject",
					},
					Claims: map[string]any{
						"groups":             "group1",
						"preferred_username": "username",
					},
				},
			},
			nil,
			types.UserInfo{},
			types.ErrInvalidClaimType,
		},
		{
			"default token with nil groups claim",
			func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Validate.Groups = []string{"group"}

				return conf
			}(),
			&oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					TokenClaims: oidc.TokenClaims{
						Subject: "subject",
					},
					Claims: map[string]any{
						"groups":             nil,
						"preferred_username": "username",
					},
				},
			},
			nil,
			types.UserInfo{
				Subject:  "subject",
				Username: "username",
			},
			nil,
		},
		{
			"custom username claim",
			func() config.Config {
				conf := config.Defaults
				conf.OAuth2.OpenVPNUsernameClaim = "sub"

				return conf
			}(),
			&oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					TokenClaims: oidc.TokenClaims{
						Subject: "subject",
					},
					Claims: map[string]any{
						"sub":                "sub",
						"preferred_username": "username",
					},
				},
			},
			nil,
			types.UserInfo{
				Subject:  "subject",
				Username: "sub",
			},
			nil,
		},
		{
			"custom username claim with invalid claim type",
			func() config.Config {
				conf := config.Defaults
				conf.OAuth2.OpenVPNUsernameClaim = "invalid"

				return conf
			}(),
			&oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					TokenClaims: oidc.TokenClaims{
						Subject: "subject",
					},
					Claims: map[string]any{
						"sub":                "sub",
						"preferred_username": "username",
					},
				},
			},
			nil,
			types.UserInfo{
				Subject:  "subject",
				Username: "sub",
			},
			types.ErrNonExistsClaim,
		},
		{
			"custom username claim",
			func() config.Config {
				conf := config.Defaults
				conf.OAuth2.OpenVPNUsernameClaim = "groups"

				return conf
			}(),
			&oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					TokenClaims: oidc.TokenClaims{
						Subject: "subject",
					},
					Claims: map[string]any{
						"groups":             []any{any("group1"), any("group2")},
						"preferred_username": "username",
					},
				},
			},
			nil,
			types.UserInfo{
				Subject:  "subject",
				Username: "sub",
			},
			types.ErrInvalidClaimType,
		},
		{
			"custom username CEL expression",
			func() config.Config {
				conf := config.Defaults
				conf.OAuth2.OpenVPNUsernameClaim = ""
				conf.OAuth2.OpenVPNUsernameCEL = "oauth2TokenClaims.sub"

				return conf
			}(),
			&oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					TokenClaims: oidc.TokenClaims{
						Subject: "subject",
					},
					Claims: map[string]any{
						"sub": "username",
					},
				},
			},
			nil,
			types.UserInfo{
				Subject:  "subject",
				Username: "username",
			},
			nil,
		},
		{
			"custom username CEL expression with string",
			func() config.Config {
				conf := config.Defaults
				conf.OAuth2.OpenVPNUsernameClaim = ""
				conf.OAuth2.OpenVPNUsernameCEL = "string(oauth2TokenClaims.groups[0])"

				return conf
			}(),
			&oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					TokenClaims: oidc.TokenClaims{
						Subject: "subject",
					},
					Claims: map[string]any{
						"groups":             []any{any("group1"), any("group2")},
						"preferred_username": "username",
					},
				},
			},
			nil,
			types.UserInfo{
				Subject:  "subject",
				Username: "group1",
			},
			nil,
		},
		{
			"invalid CEL expression",
			func() config.Config {
				conf := config.Defaults
				conf.OAuth2.OpenVPNUsernameClaim = ""
				conf.OAuth2.OpenVPNUsernameCEL = "string(oauth2TokenClaims.groups[0]"

				return conf
			}(),
			&oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					TokenClaims: oidc.TokenClaims{
						Subject: "subject",
					},
					Claims: map[string]any{
						"groups":             []any{any("group1"), any("group2")},
						"preferred_username": "username",
					},
				},
			},
			nil,
			types.UserInfo{
				Subject:  "subject",
				Username: "group1",
			},
			errors.New("failed to compile CEL expression"),
		},
		{
			"empty CEL expression and claim ",
			func() config.Config {
				conf := config.Defaults
				conf.OAuth2.OpenVPNUsernameClaim = ""
				conf.OAuth2.OpenVPNUsernameCEL = ""

				return conf
			}(),
			&oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					TokenClaims: oidc.TokenClaims{},
					Claims:      nil,
				},
			},
			nil,
			types.UserInfo{},
			nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			provider, err := generic.NewProvider(t.Context(), tc.conf, http.DefaultClient)
			if err != nil && tc.err != nil {
				require.ErrorContains(t, err, tc.err.Error())

				return
			}

			require.NoError(t, err)

			userData, err := provider.GetUser(t.Context(), slog.New(slog.DiscardHandler), tc.token, tc.userInfo)
			if tc.err == nil {
				require.NoError(t, err)
				require.Equal(t, tc.userData, userData)
			} else {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.err)
			}
		})
	}
}
