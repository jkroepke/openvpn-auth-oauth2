package github_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	types2 "github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	oauth3 "github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/github"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

const EmptyToken = "access token is empty"

func TestValidateGroups(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name           string
		userOrgs       string
		requiredGroups []string
		err            string
	}{
		{
			"empty",
			`[]`,
			make([]string, 0),
			"",
		},
		{
			"present",
			`[{ "login": "apple" }]`,
			make([]string, 0),
			"",
		},
		{
			"configure one group",
			`[{ "login": "apple" }]`,
			[]string{"apple"},
			"",
		},
		{
			EmptyToken,
			`ERROR`,
			[]string{"apple"},
			"error getting GitHub organizations: access token is empty",
		},
		{
			"http status error",
			`error`,
			[]string{"apple"},
			"error getting GitHub organizations: error from GitHub API https://api.github.com/user/orgs: http status code: 500; message: error",
		},
		{
			"invalid json",
			`ERROR`,
			[]string{"apple"},
			"error getting GitHub organizations: unable to decode JSON from GitHub API https://api.github.com/user/orgs: 'ERROR': invalid character 'E' looking for beginning of value",
		},
		{
			"configure two group, none match",
			`[{ "login": "pineapple" }]`,
			[]string{"apple", "pear"},
			oauth3.ErrMissingRequiredGroup.Error(),
		},
		{
			"configure two group, missing one",
			`[{ "login": "apple" }]`,
			[]string{"apple", "pear"},
			"",
		},
		{
			"configure two group",
			`[{ "login": "apple" },{ "login": "pear" }]`,
			[]string{"apple", "pear"},
			"",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			token := &oidc.Tokens[*idtoken.Claims]{
				Token: &oauth2.Token{
					AccessToken: "TOKEN",
				},
				IDTokenClaims: &idtoken.Claims{},
			}

			if tc.name == EmptyToken {
				token.AccessToken = ""
			}

			conf := types2.Config{
				OAuth2: types2.OAuth2{
					Validate: types2.OAuth2Validate{
						Groups: tc.requiredGroups,
					},
				},
			}

			httpClient := &http.Client{
				Transport: testutils.NewRoundTripperFunc(nil, func(_ http.RoundTripper, _ *http.Request) (*http.Response, error) {
					resp := httptest.NewRecorder()
					if strings.Contains(tc.userOrgs, "error") {
						resp.WriteHeader(http.StatusInternalServerError)
					}

					_, _ = resp.WriteString(tc.userOrgs)

					return resp.Result(), nil
				}),
			}

			provider, err := github.NewProvider(t.Context(), conf, httpClient)
			require.NoError(t, err)

			err = provider.CheckUser(t.Context(), state.State{}, types.UserInfo{Email: "ID"}, token)

			if tc.err == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestValidateRoles(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name          string
		userTeams     string
		requiredRoles []string
		err           string
	}{
		{
			"empty",
			`[]`,
			make([]string, 0),
			"",
		},
		{
			"present",
			`[{ "slug": "justice-league", "organization": { "login": "apple" }}]`,
			make([]string, 0),
			"",
		},
		{
			"configure one group",
			`[{ "slug": "justice-league", "organization": { "login": "apple" }}]`,
			[]string{"apple:justice-league"},
			"",
		},
		{
			EmptyToken,
			`ERROR`,
			[]string{"apple"},
			"error getting GitHub teams: access token is empty",
		},
		{
			"http status error",
			`error`,
			[]string{"apple"},
			"error getting GitHub teams: error from GitHub API https://api.github.com/user/teams: http status code: 500; message: error",
		},
		{
			"invalid json",
			`ERROR`,
			[]string{"apple"},
			"error getting GitHub teams: unable to decode JSON from GitHub API https://api.github.com/user/teams: 'ERROR': invalid character 'E' looking for beginning of value",
		},
		{
			"configure two group, none match",
			`[{ "slug": "justice-league", "organization": { "login": "pineapple" }}]`,
			[]string{"apple:justice-league", "pear:justice-league"},
			oauth3.ErrMissingRequiredRole.Error(),
		},
		{
			"configure two group, missing one",
			`[{ "slug": "justice-league", "organization": { "login": "apple" }}]`,
			[]string{"apple:justice-league", "pear:justice-league"},
			"",
		},
		{
			"configure two group",
			`[{ "slug": "justice-league", "organization": { "login": "apple" }},{ "slug": "justice-league", "organization": { "login": "pear" }}]`,
			[]string{"apple:justice-league", "pear:justice-league"},
			"",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			token := &oidc.Tokens[*idtoken.Claims]{
				Token: &oauth2.Token{
					AccessToken: "TOKEN",
				},
				IDTokenClaims: &idtoken.Claims{},
			}

			if tc.name == EmptyToken {
				token.AccessToken = ""
			}

			conf := types2.Config{
				OAuth2: types2.OAuth2{
					Validate: types2.OAuth2Validate{
						Roles: tc.requiredRoles,
					},
				},
			}

			httpClient := &http.Client{
				Transport: testutils.NewRoundTripperFunc(nil, func(_ http.RoundTripper, _ *http.Request) (*http.Response, error) {
					resp := httptest.NewRecorder()
					if strings.Contains(tc.userTeams, "error") {
						resp.WriteHeader(http.StatusInternalServerError)
					}

					_, _ = resp.WriteString(tc.userTeams)

					return resp.Result(), nil
				}),
			}

			provider, err := github.NewProvider(t.Context(), conf, httpClient)
			require.NoError(t, err)

			err = provider.CheckUser(t.Context(), state.State{}, types.UserInfo{Email: "ID"}, token)

			if tc.err == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}
