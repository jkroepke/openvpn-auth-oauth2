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
	"github.com/jkroepke/openvpn-auth-oauth2/internal/test/testsuite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

			token := &idtoken.IDToken{
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
				Transport: testsuite.NewRoundTripperFunc(nil, func(_ http.RoundTripper, _ *http.Request) (*http.Response, error) {
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

func TestCheckUserLoadsTeamsForCEL(t *testing.T) {
	t.Parallel()

	token := &idtoken.IDToken{
		Token: &oauth2.Token{
			AccessToken: "TOKEN",
		},
		IDTokenClaims: &idtoken.Claims{
			Claims: map[string]any{
				"login": "test-user",
			},
		},
	}

	conf := types2.Config{
		OAuth2: types2.OAuth2{
			Validate: types2.OAuth2Validate{
				Expression: "'apple:justice-league' in oauth2TokenClaims.roles",
			},
		},
	}

	var teamsCalled bool

	httpClient := &http.Client{
		Transport: testsuite.NewRoundTripperFunc(testsuite.NewMockRoundTripper(nil), func(rt http.RoundTripper, req *http.Request) (*http.Response, error) {
			if req.URL.Path != "/user/teams" {
				return rt.RoundTrip(req)
			}

			teamsCalled = true

			resp := httptest.NewRecorder()
			_, _ = resp.WriteString(`[{ "slug": "justice-league", "organization": { "login": "apple" }}]`)

			return resp.Result(), nil
		}),
	}

	provider, err := github.NewProvider(t.Context(), conf, httpClient)
	require.NoError(t, err)

	err = provider.CheckUser(t.Context(), state.State{}, types.UserInfo{Email: "ID"}, token)
	require.NoError(t, err)

	assert.True(t, teamsCalled)
	assert.Equal(t, []string{"apple:justice-league"}, token.IDTokenClaims.Claims["roles"])
	assert.Equal(t, "test-user", token.IDTokenClaims.Claims["login"])
}
