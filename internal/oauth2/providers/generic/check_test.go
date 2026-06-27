package generic_test

import (
	"log/slog"
	"net/http"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestCheckUser(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		conf     config.Config
		token    *idtoken.IDToken
		userInfo *types.UserInfo
		userData types.UserInfo
		err      error
	}{
		{
			"default token",
			config.Defaults,
			&idtoken.IDToken{
				IDTokenClaims: &idtoken.Claims{
					Claims: map[string]any{
						"preferred_username": "username",
					},
					TokenClaims: oidc.TokenClaims{
						Subject: "subject",
					},
					PreferredUsername: "username",
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
			"default token with user info",
			config.Defaults,
			&idtoken.IDToken{
				IDTokenClaims: &idtoken.Claims{
					Claims: map[string]any{
						"preferred_username": "username",
					},
					TokenClaims: oidc.TokenClaims{
						Subject: "subject",
					},
					PreferredUsername: "username",
				},
			},
			&types.UserInfo{
				Subject:  "subject",
				Username: "username2",
			},
			types.UserInfo{
				Subject:  "subject",
				Username: "username2",
			},
			nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			provider, err := generic.NewProvider(t.Context(), tc.conf, http.DefaultClient)
			require.NoError(t, err)

			userData, err := provider.GetUser(t.Context(), slog.New(slog.DiscardHandler), tc.token, tc.userInfo)
			require.NoError(t, err)
			require.Equal(t, tc.userData, userData)

			err = provider.CheckUser(t.Context(), state.State{}, userData, tc.token)
			require.NoError(t, err)
		})
	}
}

func TestInvalidToken(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		conf  config.Config
		token *idtoken.IDToken
		err   error
	}{
		{
			"nil without validation",
			config.Config{
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{},
				},
			},
			&idtoken.IDToken{
				IDTokenClaims: nil,
			},
			nil,
		},
		{
			"nil with group",
			config.Config{
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{
						Groups: []string{"apple"},
					},
				},
			},
			&idtoken.IDToken{
				IDTokenClaims: nil,
			},
			oauth2.ErrMissingClaim,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			provider, err := generic.NewProvider(t.Context(), tc.conf, http.DefaultClient)
			require.NoError(t, err)

			userData, err := provider.GetUser(t.Context(), slog.New(slog.DiscardHandler), tc.token, nil)
			require.NoError(t, err)

			err = provider.CheckUser(t.Context(), state.State{Client: state.ClientIdentifier{CommonName: "user"}}, userData, tc.token)
			if tc.err == nil {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.err)
			}
		})
	}
}

func TestValidateGroups(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name           string
		tokenGroups    []string
		requiredGroups []string
		err            string
	}{
		{"groups not present", nil, make([]string, 0), ""},
		{"groups empty", make([]string, 0), make([]string, 0), ""},
		{"groups present", []string{"apple"}, make([]string, 0), ""},
		{"configure one group", []string{"apple"}, []string{"apple"}, ""},
		{"configure one group, groups not present", nil, []string{"apple"}, "missing claim: groups"},
		{"configure two group, none match", make([]string, 0), []string{"apple", "pear"}, oauth2.ErrMissingRequiredGroup.Error()},
		{"configure two group, missing one", []string{"apple"}, []string{"apple", "pear"}, ""},
		{"configure two group", []string{"apple", "pear"}, []string{"apple", "pear"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			conf := config.Defaults
			conf.OAuth2.Validate.Groups = tc.requiredGroups

			provider, err := generic.NewProvider(t.Context(), conf, http.DefaultClient)
			require.NoError(t, err)

			err = provider.CheckGroups(types.UserInfo{
				Groups: tc.tokenGroups,
			})

			if tc.err == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Equal(t, tc.err, err.Error())
			}
		})
	}
}
