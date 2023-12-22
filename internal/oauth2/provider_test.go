package oauth2_test

import (
	"crypto/sha256"
	"net"
	"net/http/httptest"
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
	serverStorage "github.com/zitadel/oidc/v3/example/server/storage"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/text/language"
)

func TestNewProvider(t *testing.T) {
	t.Parallel()

	opStorage := serverStorage.NewStorageWithClients(serverStorage.NewUserStore("http://localhost"), map[string]*serverStorage.Client{})
	opConfig := &op.Config{
		CryptoKey:                sha256.Sum256([]byte("test")),
		DefaultLogoutRedirectURI: "/",
		CodeMethodS256:           true,
		AuthMethodPost:           true,
		AuthMethodPrivateKeyJWT:  true,
		GrantTypeRefreshToken:    true,
		RequestObjectSupported:   true,
		SupportedUILocales:       []language.Tag{language.English},
	}

	handler, err := op.NewProvider(opConfig, opStorage, op.IssuerFromHost(""), op.WithAllowInsecure())

	require.NoError(t, err)

	svr := httptest.NewServer(handler)
	logger := testutils.NewTestLogger()

	svrURL, _ := url.Parse(svr.URL)

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
					Issuer:    svrURL,
					Provider:  generic.Name,
					Client:    config.OAuth2Client{ID: "ID", Secret: "ID"},
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
					Issuer:   svrURL,
					Provider: generic.Name,
					Client:   config.OAuth2Client{ID: "ID", Secret: "ID"},
					Endpoints: config.OAuth2Endpoints{
						Discovery: &url.URL{Scheme: svrURL.Scheme, Host: svrURL.Host, Path: "/.well-known/openid-configuration"},
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
					Issuer:   svrURL,
					Provider: generic.Name,
					Client:   config.OAuth2Client{ID: "ID", Secret: "ID"},
					Endpoints: config.OAuth2Endpoints{
						Discovery: &url.URL{Scheme: svrURL.Scheme, Host: svrURL.Host, Path: "/.well-known/openid-config"},
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
					Issuer:   svrURL,
					Provider: generic.Name,
					Client:   config.OAuth2Client{ID: "ID", Secret: "ID"},
					Endpoints: config.OAuth2Endpoints{
						Discovery: &url.URL{Scheme: svrURL.Scheme, Host: svrURL.Host, Path: "/.well-known/openid-configuration"},
						Auth:      &url.URL{Scheme: svrURL.Scheme, Host: svrURL.Host, Path: "/authorize"},
						Token:     &url.URL{Scheme: svrURL.Scheme, Host: svrURL.Host, Path: "/token"},
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
					Issuer:   svrURL,
					Provider: generic.Name,
					Client:   config.OAuth2Client{ID: "ID", Secret: "ID"},
					Endpoints: config.OAuth2Endpoints{
						Discovery: &url.URL{Scheme: svrURL.Scheme, Host: svrURL.Host, Path: "/.well-known/openid-configuration"},
						Auth:      &url.URL{Scheme: svrURL.Scheme, Host: svrURL.Host, Path: "/authorize"},
					},
				},
			},
			"error getting endpoints: both oauth2.endpoints.tokenUrl and oauth2.endpoints.authUrl are required",
		},
		{
			"with pkce",
			config.Config{
				HTTP: config.HTTP{BaseURL: &url.URL{Scheme: "http", Host: "localhost"}},
				OAuth2: config.OAuth2{
					Issuer:   svrURL,
					Provider: generic.Name,
					Pkce:     true,
					Client:   config.OAuth2Client{ID: "ID", Secret: "ID"},
					Endpoints: config.OAuth2Endpoints{
						Discovery: &url.URL{Scheme: svrURL.Scheme, Host: svrURL.Host, Path: "/.well-known/openid-configuration"},
						Auth:      &url.URL{Scheme: svrURL.Scheme, Host: svrURL.Host, Path: "/authorize"},
						Token:     &url.URL{Scheme: svrURL.Scheme, Host: svrURL.Host, Path: "/token"},
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

			storageClient := storage.New("0123456789101112", time.Hour)

			provider := oauth2.New(logger, tt.conf, storageClient)

			client := openvpn.NewClient(logger, tt.conf, provider)
			defer client.Shutdown()

			err = provider.Discover(client)
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
