package oauth2_test

import (
	"context"
	"net"
	http2 "net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/storage"
	"github.com/jkroepke/openvpn-auth-oauth2/pkg/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/nettest"
)

func TestNewProvider(t *testing.T) {
	t.Parallel()

	clientListener, err := nettest.NewLocalListener("tcp")
	require.NoError(t, err)

	_, resourceServerURL, clientCredentials, err := testutils.SetupResourceServer(t, clientListener)
	require.NoError(t, err)

	logger := testutils.NewTestLogger()

	tests := []struct {
		name string
		conf config.Config
		err  string
	}{
		{
			"default",
			config.Config{
				HTTP: config.HTTP{BaseURL: &url.URL{Scheme: "http", Host: "localhost"}},
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
				HTTP: config.HTTP{BaseURL: &url.URL{Scheme: "http", Host: "localhost"}},
				OAuth2: config.OAuth2{
					Issuer:   resourceServerURL,
					Provider: generic.Name,
					Client:   clientCredentials,
					Endpoints: config.OAuth2Endpoints{
						Discovery: &url.URL{Scheme: resourceServerURL.Scheme, Host: resourceServerURL.Host, Path: "/.well-known/openid-configuration"},
					},
				},
			},
			"",
		},
		{
			"with invalid custom discovery",
			config.Config{
				HTTP: config.HTTP{BaseURL: &url.URL{Scheme: "http", Host: "localhost"}},
				OAuth2: config.OAuth2{
					Issuer:   resourceServerURL,
					Provider: generic.Name,
					Client:   clientCredentials,
					Endpoints: config.OAuth2Endpoints{
						Discovery: &url.URL{Scheme: resourceServerURL.Scheme, Host: resourceServerURL.Host, Path: "/.well-known/openid-config"},
					},
				},
			},
			"error oauth2 provider: http status not ok: 404 Not Found 404 page not found",
		},
		{
			"with custom endpoints",
			config.Config{
				HTTP: config.HTTP{BaseURL: &url.URL{Scheme: "http", Host: "localhost"}},
				OAuth2: config.OAuth2{
					Issuer:   resourceServerURL,
					Provider: generic.Name,
					Client:   clientCredentials,
					Endpoints: config.OAuth2Endpoints{
						Discovery: &url.URL{Scheme: resourceServerURL.Scheme, Host: resourceServerURL.Host, Path: "/.well-known/openid-configuration"},
						Auth:      &url.URL{Scheme: resourceServerURL.Scheme, Host: resourceServerURL.Host, Path: "/authorize"},
						Token:     &url.URL{Scheme: resourceServerURL.Scheme, Host: resourceServerURL.Host, Path: "/token"},
					},
				},
			},
			"",
		},
		{
			"with missing custom endpoints",
			config.Config{
				HTTP: config.HTTP{BaseURL: &url.URL{Scheme: "http", Host: "localhost"}},
				OAuth2: config.OAuth2{
					Issuer:   resourceServerURL,
					Provider: generic.Name,
					Client:   clientCredentials,
					Endpoints: config.OAuth2Endpoints{
						Discovery: &url.URL{Scheme: resourceServerURL.Scheme, Host: resourceServerURL.Host, Path: "/.well-known/openid-configuration"},
						Auth:      &url.URL{Scheme: resourceServerURL.Scheme, Host: resourceServerURL.Host, Path: "/authorize"},
					},
				},
			},
			"error getting providerConfig: both oauth2.endpoints.tokenUrl and oauth2.endpoints.authUrl are required",
		},
		{
			"with pkce",
			config.Config{
				HTTP: config.HTTP{BaseURL: &url.URL{Scheme: "http", Host: "localhost"}},
				OAuth2: config.OAuth2{
					Issuer:   resourceServerURL,
					Provider: generic.Name,
					Pkce:     true,
					Client:   clientCredentials,
					Endpoints: config.OAuth2Endpoints{
						Discovery: &url.URL{Scheme: resourceServerURL.Scheme, Host: resourceServerURL.Host, Path: "/.well-known/openid-configuration"},
						Auth:      &url.URL{Scheme: resourceServerURL.Scheme, Host: resourceServerURL.Host, Path: "/authorize"},
						Token:     &url.URL{Scheme: resourceServerURL.Scheme, Host: resourceServerURL.Host, Path: "/token"},
					},
				},
			},
			"",
		},
	}
	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			managementInterface, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)

			defer managementInterface.Close()

			tt.conf.OpenVpn.Addr = &url.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}

			storageClient := storage.New(testutils.Secret, time.Hour)

			provider := oauth2.New(logger.Logger, tt.conf, storageClient, http2.DefaultClient)

			client := openvpn.NewClient(context.Background(), logger.Logger, tt.conf, provider)
			defer client.Shutdown()

			err = provider.Initialize(client)
			if tt.err != "" {
				require.Error(t, err)
				assert.Equal(t, tt.err, strings.TrimSpace(err.Error()))

				return
			}

			require.NoError(t, err)

			assert.Equal(t, provider.OAuthConfig().ClientID, tt.conf.OAuth2.Client.ID)
			assert.Equal(t, provider.OAuthConfig().ClientSecret, tt.conf.OAuth2.Client.Secret.String())

			if tt.conf.OAuth2.Endpoints.Auth != nil {
				assert.Equal(t, provider.OAuthConfig().Endpoint.AuthURL, tt.conf.OAuth2.Endpoints.Auth.String())
			} else {
				assert.NotEmpty(t, provider.OAuthConfig().Endpoint.AuthURL)
			}

			if tt.conf.OAuth2.Endpoints.Token != nil {
				assert.Equal(t, provider.OAuthConfig().Endpoint.TokenURL, tt.conf.OAuth2.Endpoints.Token.String())
			} else {
				assert.NotEmpty(t, provider.OAuthConfig().Endpoint.TokenURL)
			}
		})
	}
}
