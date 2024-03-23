package github_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/github"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/pkg/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

func TestGetUser(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name     string
		user     string
		userData types.UserData
		err      string
	}{
		{
			"user",
			`{"login": "login","email": "email","id": 10}`,
			types.UserData{
				PreferredUsername: "login",
				Email:             "email",
				Subject:           "10",
			},
			"",
		},
		{
			"access token is empty",
			`ERROR`,
			types.UserData{},
			"access token is empty",
		},
		{
			"http status error",
			`error`,
			types.UserData{},
			"error from GitHub API https://api.github.com/user: http status code: 500; message: error",
		},
		{
			"invalid json",
			`ERROR`,
			types.UserData{},
			"unable to decode JSON from GitHub API https://api.github.com/user: 'ERROR': invalid character 'E' looking for beginning of value",
		},
	} {
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
						Groups: []string{},
						Roles:  []string{},
					},
				},
			}

			httpClient := &http.Client{
				Transport: testutils.NewRoundTripperFunc(func(_ *http.Request) (*http.Response, error) {
					resp := httptest.NewRecorder()
					if strings.Contains(tt.user, "error") {
						resp.WriteHeader(http.StatusInternalServerError)
					}

					_, _ = resp.WriteString(tt.user)

					return resp.Result(), nil
				}),
			}

			provider, err := github.NewProvider(context.Background(), conf, httpClient)
			require.NoError(t, err)

			userData, err := provider.GetUser(context.Background(), testutils.NewTestLogger().Logger, token)

			if tt.err == "" {
				require.NoError(t, err)
				assert.Equal(t, tt.userData, userData)
			} else {
				require.Error(t, err)
				assert.EqualError(t, err, tt.err)
			}
		})
	}
}
