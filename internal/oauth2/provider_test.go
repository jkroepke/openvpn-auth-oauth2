package oauth2_test

import (
	"crypto/sha256"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/pkg/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/example/server/storage"
	"github.com/zitadel/oidc/v3/pkg/op"
	"golang.org/x/text/language"
)

func TestNewProvider(t *testing.T) {
	t.Parallel()

	opStorage := storage.NewStorageWithClients(storage.NewUserStore("http://localhost"), map[string]*storage.Client{})
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
		name   string
		config config.Config
		err    string
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
			"newProviderWithDiscovery: http status not ok: 404 Not Found 404 page not found",
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

			provider, err := oauth2.NewProvider(logger, tt.config)
			if tt.err != "" {
				require.Error(t, err)
				assert.Equal(t, strings.TrimSpace(err.Error()), tt.err)

				return
			}

			require.NoError(t, err)

			assert.Equal(t, provider.OAuthConfig().ClientID, tt.config.OAuth2.Client.ID)
			assert.Equal(t, provider.OAuthConfig().ClientSecret, tt.config.OAuth2.Client.Secret.String())
			if tt.config.OAuth2.Endpoints.Auth != nil {
				assert.Equal(t, provider.OAuthConfig().Endpoint.AuthURL, tt.config.OAuth2.Endpoints.Auth.String())
			} else {
				assert.NotEmpty(t, provider.OAuthConfig().Endpoint.AuthURL)
			}
			if tt.config.OAuth2.Endpoints.Token != nil {
				assert.Equal(t, provider.OAuthConfig().Endpoint.TokenURL, tt.config.OAuth2.Endpoints.Token.String())
			} else {
				assert.NotEmpty(t, provider.OAuthConfig().Endpoint.TokenURL)
			}
		})
	}
}
