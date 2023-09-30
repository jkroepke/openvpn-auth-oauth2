package oauth2

import (
	"crypto/sha256"
	"io"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/stretchr/testify/assert"
	"github.com/zitadel/oidc/v2/example/server/storage"
	"github.com/zitadel/oidc/v2/pkg/op"
	"golang.org/x/text/language"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
)

func TestNewProvider(t *testing.T) {
	opStorage := storage.NewStorage(storage.NewUserStore("http://localhost/"))
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

	handler, err := op.NewDynamicOpenIDProvider("", opConfig, opStorage,
		op.WithAllowInsecure(),
	)

	assert.NoError(t, err)
	svr := httptest.NewServer(handler.HttpHandler())
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	svrUrl, _ := url.Parse(svr.URL)

	configs := []struct {
		name   string
		config config.Config
		err    string
	}{
		{
			"default",
			config.Config{
				Http: &config.Http{BaseUrl: &url.URL{Scheme: "http", Host: "localhost"}},
				Oauth2: &config.OAuth2{
					Issuer:    svrUrl,
					Provider:  generic.Name,
					Client:    &config.OAuth2Client{Id: "ID", Secret: "ID"},
					Endpoints: &config.OAuth2Endpoints{},
				},
			},
			"",
		},
		{
			"with custom discovery",
			config.Config{
				Http: &config.Http{BaseUrl: &url.URL{Scheme: "http", Host: "localhost"}},
				Oauth2: &config.OAuth2{
					Issuer:   svrUrl,
					Provider: generic.Name,
					Client:   &config.OAuth2Client{Id: "ID", Secret: "ID"},
					Endpoints: &config.OAuth2Endpoints{
						Discovery: &url.URL{Scheme: svrUrl.Scheme, Host: svrUrl.Host, Path: "/.well-known/openid-configuration"},
					},
				},
			},
			"",
		},
		{
			"with invalid custom discovery",
			config.Config{
				Http: &config.Http{BaseUrl: &url.URL{Scheme: "http", Host: "localhost"}},
				Oauth2: &config.OAuth2{
					Issuer:   svrUrl,
					Provider: generic.Name,
					Client:   &config.OAuth2Client{Id: "ID", Secret: "ID"},
					Endpoints: &config.OAuth2Endpoints{
						Discovery: &url.URL{Scheme: svrUrl.Scheme, Host: svrUrl.Host, Path: "/.well-known/openid-config"},
					},
				},
			},
			"http status not ok: 404 Not Found 404 page not found",
		},
		{
			"with custom endpoints",
			config.Config{
				Http: &config.Http{BaseUrl: &url.URL{Scheme: "http", Host: "localhost"}},
				Oauth2: &config.OAuth2{
					Issuer:   svrUrl,
					Provider: generic.Name,
					Client:   &config.OAuth2Client{Id: "ID", Secret: "ID"},
					Endpoints: &config.OAuth2Endpoints{
						Discovery: &url.URL{Scheme: svrUrl.Scheme, Host: svrUrl.Host, Path: "/.well-known/openid-configuration"},
						Auth:      &url.URL{Scheme: svrUrl.Scheme, Host: svrUrl.Host, Path: "/authorize"},
						Token:     &url.URL{Scheme: svrUrl.Scheme, Host: svrUrl.Host, Path: "/token"},
					},
				},
			},
			"",
		},
		{
			"with missing custom endpoints",
			config.Config{
				Http: &config.Http{BaseUrl: &url.URL{Scheme: "http", Host: "localhost"}},
				Oauth2: &config.OAuth2{
					Issuer:   svrUrl,
					Provider: generic.Name,
					Client:   &config.OAuth2Client{Id: "ID", Secret: "ID"},
					Endpoints: &config.OAuth2Endpoints{
						Discovery: &url.URL{Scheme: svrUrl.Scheme, Host: svrUrl.Host, Path: "/.well-known/openid-configuration"},
						Auth:      &url.URL{Scheme: svrUrl.Scheme, Host: svrUrl.Host, Path: "/authorize"},
					},
				},
			},
			"both oauth2.endpoints.tokenUrl and oauth2.endpoints.authUrl are required",
		},
		{
			"with pkce",
			config.Config{
				Http: &config.Http{BaseUrl: &url.URL{Scheme: "http", Host: "localhost"}},
				Oauth2: &config.OAuth2{
					Issuer:   svrUrl,
					Provider: generic.Name,
					Pkce:     true,
					Client:   &config.OAuth2Client{Id: "ID", Secret: "ID"},
					Endpoints: &config.OAuth2Endpoints{
						Discovery: &url.URL{Scheme: svrUrl.Scheme, Host: svrUrl.Host, Path: "/.well-known/openid-configuration"},
						Auth:      &url.URL{Scheme: svrUrl.Scheme, Host: svrUrl.Host, Path: "/authorize"},
						Token:     &url.URL{Scheme: svrUrl.Scheme, Host: svrUrl.Host, Path: "/token"},
					},
				},
			},
			"",
		},
	}
	for _, tt := range configs {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewProvider(logger, tt.config)
			if tt.err != "" && assert.Error(t, err) {
				assert.Equal(t, strings.TrimSpace(err.Error()), tt.err)
				return
			}

			assert.NoError(t, err)

			assert.Equal(t, provider.OAuthConfig().ClientID, tt.config.Oauth2.Client.Id)
			assert.Equal(t, provider.OAuthConfig().ClientSecret, tt.config.Oauth2.Client.Secret)
			if tt.config.Oauth2.Endpoints.Auth != nil {
				assert.Equal(t, provider.OAuthConfig().Endpoint.AuthURL, tt.config.Oauth2.Endpoints.Auth.String())
			} else {
				assert.NotEmpty(t, provider.OAuthConfig().Endpoint.AuthURL)
			}
			if tt.config.Oauth2.Endpoints.Token != nil {
				assert.Equal(t, provider.OAuthConfig().Endpoint.TokenURL, tt.config.Oauth2.Endpoints.Token.String())
			} else {
				assert.NotEmpty(t, provider.OAuthConfig().Endpoint.TokenURL)
			}
		})
	}
}
