package oauth2_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/authentik"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/github"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/google"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/nettest"
)

func TestNewProvider(t *testing.T) {
	t.Parallel()

	clientListener, err := nettest.NewLocalListener("tcp")
	require.NoError(t, err)

	_, resourceServerURL, clientCredentials, err := testutils.SetupResourceServer(t, clientListener, nil, nil)
	require.NoError(t, err)

	tests := []struct {
		name string
		conf config.Config
		err  string
	}{
		{
			"default",
			config.Config{
				HTTP: config.HTTP{BaseURL: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}},
				OAuth2: config.OAuth2{
					Issuer:    resourceServerURL,
					Provider:  generic.Name,
					Client:    clientCredentials,
					Endpoints: config.OAuth2Endpoints{},
				},
			},
			"",
		},
		{
			"with custom discovery",
			config.Config{
				HTTP: config.HTTP{BaseURL: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}},
				OAuth2: config.OAuth2{
					Issuer:   resourceServerURL,
					Provider: generic.Name,
					Client:   clientCredentials,
					Endpoints: config.OAuth2Endpoints{
						Discovery: types.URL{URL: &url.URL{Scheme: resourceServerURL.Scheme, Host: resourceServerURL.Host, Path: "/.well-known/openid-configuration"}},
					},
				},
			},
			"",
		},
		{
			"with invalid custom discovery",
			config.Config{
				HTTP: config.HTTP{BaseURL: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}},
				OAuth2: config.OAuth2{
					Issuer:   resourceServerURL,
					Provider: generic.Name,
					Client:   clientCredentials,
					Endpoints: config.OAuth2Endpoints{
						Discovery: types.URL{URL: &url.URL{Scheme: resourceServerURL.Scheme, Host: resourceServerURL.Host, Path: "/.well-known/openid-config"}},
					},
				},
			},
			"error oidc provider: OpenID Provider Configuration Discovery has failed\nhttp status not ok: 404 Not Found 404 page not found",
		},
		{
			"with custom endpoints",
			config.Config{
				HTTP: config.HTTP{BaseURL: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}},
				OAuth2: config.OAuth2{
					Issuer:   resourceServerURL,
					Provider: generic.Name,
					Client:   clientCredentials,
					Endpoints: config.OAuth2Endpoints{
						Discovery: types.URL{URL: &url.URL{Scheme: resourceServerURL.Scheme, Host: resourceServerURL.Host, Path: "/.well-known/openid-configuration"}},
						Auth:      types.URL{URL: &url.URL{Scheme: resourceServerURL.Scheme, Host: resourceServerURL.Host, Path: "/authorize"}},
						Token:     types.URL{URL: &url.URL{Scheme: resourceServerURL.Scheme, Host: resourceServerURL.Host, Path: "/token"}},
					},
				},
			},
			"",
		},
		{
			name: "with missing custom endpoints",
			conf: config.Config{
				HTTP: config.HTTP{
					BaseURL: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
				},
				OAuth2: config.OAuth2{
					Issuer:   resourceServerURL,
					Provider: generic.Name,
					Client:   clientCredentials,
					Endpoints: config.OAuth2Endpoints{
						Discovery: types.URL{URL: &url.URL{Scheme: resourceServerURL.Scheme, Host: resourceServerURL.Host, Path: "/.well-known/openid-configuration"}},
						Auth:      types.URL{URL: &url.URL{Scheme: resourceServerURL.Scheme, Host: resourceServerURL.Host, Path: "/authorize"}},
					},
				},
			},
			err: "error fetch configuration for provider generic: both oauth2.endpoints.tokenUrl and oauth2.endpoints.authUrl are required",
		},
		{
			name: "with pkce",
			conf: config.Config{
				HTTP: config.HTTP{BaseURL: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}},
				OAuth2: config.OAuth2{
					Issuer:   resourceServerURL,
					Provider: generic.Name,
					PKCE:     true,
					Client:   clientCredentials,
					Endpoints: config.OAuth2Endpoints{
						Discovery: types.URL{URL: &url.URL{Scheme: resourceServerURL.Scheme, Host: resourceServerURL.Host, Path: "/.well-known/openid-configuration"}},
						Auth:      types.URL{URL: &url.URL{Scheme: resourceServerURL.Scheme, Host: resourceServerURL.Host, Path: "/authorize"}},
						Token:     types.URL{URL: &url.URL{Scheme: resourceServerURL.Scheme, Host: resourceServerURL.Host, Path: "/token"}},
					},
				},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)

			logger := testutils.NewTestLogger()

			var (
				err      error
				provider oauth2.Provider
			)

			switch tc.conf.OAuth2.Provider {
			case authentik.Name:
				provider, err = authentik.NewProvider(ctx, tc.conf, http.DefaultClient)
			case generic.Name:
				provider, err = generic.NewProvider(ctx, tc.conf, http.DefaultClient)
			case github.Name:
				provider, err = github.NewProvider(ctx, tc.conf, http.DefaultClient)
			case google.Name:
				provider, err = google.NewProvider(ctx, tc.conf, http.DefaultClient)
			default:
				t.Fatal("unknown oauth2 provider: " + tc.conf.OAuth2.Provider)
			}

			require.NoError(t, err)

			oAuth2Client, err := oauth2.New(ctx, logger.Logger, tc.conf, http.DefaultClient, testutils.NewFakeStorage(), provider, testutils.NewFakeOpenVPNClient())
			if tc.err != "" {
				require.Error(t, err)
				assert.Equal(t, tc.err, strings.TrimSpace(err.Error()))

				return
			}

			assert.Equal(t, oAuth2Client.OAuthConfig().ClientID, tc.conf.OAuth2.Client.ID)
			assert.Equal(t, oAuth2Client.OAuthConfig().ClientSecret, tc.conf.OAuth2.Client.Secret.String())

			if !tc.conf.OAuth2.Endpoints.Auth.IsEmpty() {
				assert.Equal(t, oAuth2Client.OAuthConfig().Endpoint.AuthURL, tc.conf.OAuth2.Endpoints.Auth.String())
			} else {
				assert.NotEmpty(t, oAuth2Client.OAuthConfig().Endpoint.AuthURL)
			}

			if !tc.conf.OAuth2.Endpoints.Token.IsEmpty() {
				assert.Equal(t, oAuth2Client.OAuthConfig().Endpoint.TokenURL, tc.conf.OAuth2.Endpoints.Token.String())
			} else {
				assert.NotEmpty(t, oAuth2Client.OAuthConfig().Endpoint.TokenURL)
			}
		})
	}
}
