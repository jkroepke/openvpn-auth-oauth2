package github_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/github"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/pkg/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

func TestValidateGroups(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name           string
		userOrgs       string
		requiredGroups []string
		err            string
	}{
		{
			"empty",
			`[]`,
			[]string{},
			"",
		},
		{
			"present",
			`[{ "login": "apple" }]`,
			[]string{},
			"",
		},
		{
			"configure one group",
			`[{ "login": "apple" }]`,
			[]string{"apple"},
			"",
		},
		{
			"access token is empty",
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
			generic.ErrMissingRequiredGroup.Error(),
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
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			token := &oidc.Tokens[*idtoken.Claims]{
				Token: &oauth2.Token{
					AccessToken: "TOKEN",
				},
				IDTokenClaims: &idtoken.Claims{},
			}

			if tt.name == "access token is empty" {
				token.AccessToken = ""
			}

			conf := config.Config{
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{
						Groups: tt.requiredGroups,
					},
				},
			}

			httpClient := &http.Client{
				Transport: testutils.NewRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
					resp := httptest.NewRecorder()
					if strings.Contains(tt.userOrgs, "error") {
						resp.WriteHeader(http.StatusInternalServerError)
					}

					_, _ = resp.WriteString(tt.userOrgs)

					return resp.Result(), nil
				}),
			}

			provider, err := github.NewProvider(context.Background(), conf, httpClient)
			require.NoError(t, err)

			err = provider.CheckUser(context.Background(), state.State{}, types.UserData{Email: "ID"}, token)

			if tt.err == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.EqualError(t, err, tt.err)
			}
		})
	}
}

func TestValidateRoles(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name          string
		userTeams     string
		requiredRoles []string
		err           string
	}{
		{
			"empty",
			`[]`,
			[]string{},
			"",
		},
		{
			"present",
			`[{ "slug": "justice-league", "organization": { "login": "apple" }}]`,
			[]string{},
			"",
		},
		{
			"configure one group",
			`[{ "slug": "justice-league", "organization": { "login": "apple" }}]`,
			[]string{"apple:justice-league"},
			"",
		},
		{
			"access token is empty",
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
			generic.ErrMissingRequiredRole.Error(),
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
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			token := &oidc.Tokens[*idtoken.Claims]{
				Token: &oauth2.Token{
					AccessToken: "TOKEN",
				},
				IDTokenClaims: &idtoken.Claims{},
			}

			if tt.name == "access token is empty" {
				token.AccessToken = ""
			}

			conf := config.Config{
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{
						Roles: tt.requiredRoles,
					},
				},
			}

			httpClient := &http.Client{
				Transport: testutils.NewRoundTripperFunc(func(_ *http.Request) (*http.Response, error) {
					resp := httptest.NewRecorder()
					if strings.Contains(tt.userTeams, "error") {
						resp.WriteHeader(http.StatusInternalServerError)
					}

					_, _ = resp.WriteString(tt.userTeams)

					return resp.Result(), nil
				}),
			}

			provider, err := github.NewProvider(context.Background(), conf, httpClient)
			require.NoError(t, err)

			err = provider.CheckUser(context.Background(), state.State{}, types.UserData{Email: "ID"}, token)

			if tt.err == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.EqualError(t, err, tt.err)
			}
		})
	}
}
