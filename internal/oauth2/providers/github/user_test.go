package github_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	types2 "github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/providers/github"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/test/testsuite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

func TestGetUser(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		user     string
		userData types.UserInfo
		err      string
	}{
		{
			"user",
			`{"login": "login","email": "email","id": 10}`,
			types.UserInfo{
				Username: "login",
				Email:    "email",
				Subject:  "10",
				Groups:   []string{"apple"},
				Roles:    []string{"apple:justice-league"},
			},
			"",
		},
		{
			"access token is empty",
			`ERROR`,
			types.UserInfo{},
			"access token is empty",
		},
		{
			"http status error",
			`error`,
			types.UserInfo{},
			"error from GitHub API https://api.github.com/user: http status code: 500; message: error",
		},
		{
			"invalid json",
			`ERROR`,
			types.UserInfo{},
			"unable to decode JSON from GitHub API https://api.github.com/user: 'ERROR': invalid character 'E' looking for beginning of value",
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

			if tc.name == "access token is empty" {
				token.AccessToken = ""
			}

			conf := types2.Config{
				OAuth2: types2.OAuth2{
					Validate: types2.OAuth2Validate{
						Groups:     make([]string, 0),
						Expression: "'apple' in user.groups && 'apple:justice-league' in user.roles",
					},
				},
			}

			httpClient := &http.Client{
				Transport: testsuite.NewRoundTripperFunc(nil, func(_ http.RoundTripper, req *http.Request) (*http.Response, error) {
					resp := httptest.NewRecorder()

					switch req.URL.Path {
					case "/user":
						if strings.Contains(tc.user, "error") {
							resp.WriteHeader(http.StatusInternalServerError)
						}

						_, _ = resp.WriteString(tc.user)
					case "/user/orgs":
						_, _ = resp.WriteString(`[{ "login": "apple" }]`)
					case "/user/teams":
						_, _ = resp.WriteString(`[{ "slug": "justice-league", "organization": { "login": "apple" }}]`)
					}

					return resp.Result(), nil
				}),
			}

			provider, err := github.NewProvider(t.Context(), &conf, httpClient)
			require.NoError(t, err)

			userData, err := provider.GetUser(t.Context(), nil, token, nil)

			if tc.err == "" {
				require.NoError(t, err)
				assert.Equal(t, tc.userData, userData)
			} else {
				require.Error(t, err)
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestGetUserSkipsUnusedOrganizationAndTeamLookups(t *testing.T) {
	t.Parallel()

	token := &idtoken.IDToken{
		Token: &oauth2.Token{AccessToken: "TOKEN"},
	}
	conf := types2.Config{
		OAuth2: types2.OAuth2{OpenVPNUsername: "user.username"},
	}

	var requests atomic.Int32

	httpClient := &http.Client{
		Transport: testsuite.NewRoundTripperFunc(nil, func(_ http.RoundTripper, req *http.Request) (*http.Response, error) {
			requests.Add(1)
			require.Equal(t, "/user", req.URL.Path)

			resp := httptest.NewRecorder()
			_, _ = resp.WriteString(`{"login": "login", "email": "email", "id": 10}`)

			return resp.Result(), nil
		}),
	}

	provider, err := github.NewProvider(t.Context(), &conf, httpClient)
	require.NoError(t, err)

	user, err := provider.GetUser(t.Context(), nil, token, nil)

	require.NoError(t, err)
	require.Equal(t, "login", user.Username)
	require.EqualValues(t, 1, requests.Load())
}
