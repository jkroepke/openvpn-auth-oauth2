package oauth2

import (
	"crypto/sha256"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

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

	configs := []struct {
		name   string
		config *config.Config
		err    string
	}{
		{
			"default",
			&config.Config{
				Http: &config.Http{BaseUrl: "http://localhost/"},
				Oauth2: &config.OAuth2{
					Issuer:    svr.URL,
					Provider:  "oidc",
					Client:    &config.OAuth2Client{Id: "ID", Secret: "ID"},
					Endpoints: &config.OAuth2Endpoints{},
				},
			},
			"",
		},
		{
			"with custom discovery",
			&config.Config{
				Http: &config.Http{BaseUrl: "http://localhost/"},
				Oauth2: &config.OAuth2{
					Issuer:   svr.URL,
					Provider: "oidc",
					Client:   &config.OAuth2Client{Id: "ID", Secret: "ID"},
					Endpoints: &config.OAuth2Endpoints{
						Discovery: svr.URL + "/.well-known/openid-configuration",
					},
				},
			},
			"",
		},
		{
			"with invalid custom discovery",
			&config.Config{
				Http: &config.Http{BaseUrl: "http://localhost/"},
				Oauth2: &config.OAuth2{
					Issuer:   svr.URL,
					Provider: "oidc",
					Client:   &config.OAuth2Client{Id: "ID", Secret: "ID"},
					Endpoints: &config.OAuth2Endpoints{
						Discovery: svr.URL + "/.well-known/openid-config",
					},
				},
			},
			"http status not ok: 404 Not Found 404 page not found",
		},
		{
			"with custom endpoints",
			&config.Config{
				Http: &config.Http{BaseUrl: "http://localhost/"},
				Oauth2: &config.OAuth2{
					Issuer:   svr.URL,
					Provider: "oidc",
					Client:   &config.OAuth2Client{Id: "ID", Secret: "ID"},
					Endpoints: &config.OAuth2Endpoints{
						Discovery: svr.URL + "/.well-known/openid-config",
						Auth:      svr.URL + "/.well-known/authorize",
						Token:     svr.URL + "/.well-known/token",
					},
				},
			},
			"",
		},
		{
			"with invalid base url",
			&config.Config{
				Http: &config.Http{BaseUrl: "http://-"},
				Oauth2: &config.OAuth2{
					Issuer:   svr.URL,
					Provider: "oidc",
					Client:   &config.OAuth2Client{Id: "ID", Secret: "ID"},
					Endpoints: &config.OAuth2Endpoints{
						Discovery: svr.URL + "/.well-known/openid-config",
						Auth:      svr.URL + "/.well-known/authorize",
						Token:     svr.URL + "/.well-known/token",
					},
				},
			},
			"",
		},
		{
			"with pkce",
			&config.Config{
				Http: &config.Http{BaseUrl: "http://localhost/"},
				Oauth2: &config.OAuth2{
					Issuer:   svr.URL,
					Provider: "oidc",
					Pkce:     true,
					Client:   &config.OAuth2Client{Id: "ID", Secret: "ID"},
					Endpoints: &config.OAuth2Endpoints{
						Discovery: svr.URL + "/.well-known/openid-config",
						Auth:      svr.URL + "/.well-known/authorize",
						Token:     svr.URL + "/.well-known/token",
					},
				},
			},
			"",
		},
	}
	for _, tt := range configs {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewProvider(logger, tt.config)
			if tt.err != "" {
				assert.Equal(t, strings.TrimSpace(err.Error()), tt.err)
				return
			}

			assert.NoError(t, err)

			assert.Equal(t, provider.OAuthConfig().ClientID, tt.config.Oauth2.Client.Id)
			assert.Equal(t, provider.OAuthConfig().ClientSecret, tt.config.Oauth2.Client.Secret)
			if tt.config.Oauth2.Endpoints.Auth != "" {
				assert.Equal(t, provider.OAuthConfig().Endpoint.AuthURL, tt.config.Oauth2.Endpoints.Auth)
			} else {
				assert.NotEmpty(t, provider.OAuthConfig().Endpoint.AuthURL)
			}
			if tt.config.Oauth2.Endpoints.Token != "" {
				assert.Equal(t, provider.OAuthConfig().Endpoint.TokenURL, tt.config.Oauth2.Endpoints.Token)
			} else {
				assert.NotEmpty(t, provider.OAuthConfig().Endpoint.TokenURL)
			}
		})
	}
}
