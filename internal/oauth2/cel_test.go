package oauth2_test

import (
	"log/slog"
	"net/http"
	"net/url"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/providers/generic"
	oauth2types "github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/test/testsuite"
	"github.com/stretchr/testify/require"
)

func TestCheckIdentityCEL(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		conf  config.Config
		state state.State
		token *idtoken.IDToken
		user  oauth2types.UserInfo
		err   string
	}{
		{
			name: "no CEL expression configured",
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Issuer = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
				conf.OAuth2.Endpoints.Discovery = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Auth = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Token = conf.OAuth2.Issuer

				return conf
			}(),
		},
		{
			name: "empty CEL expression configured",
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Issuer = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
				conf.OAuth2.Endpoints.Discovery = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Auth = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Token = conf.OAuth2.Issuer
				conf.OAuth2.Validate.Expression = ""

				return conf
			}(),
		},
		{
			name: "invalid CEL expression configured",
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Issuer = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
				conf.OAuth2.Endpoints.Discovery = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Auth = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Token = conf.OAuth2.Issuer
				conf.OAuth2.Validate.Expression = "-"

				return conf
			}(),
		},
		{
			name: "UserInfo identity without ID token claims",
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Issuer = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
				conf.OAuth2.Endpoints.Discovery = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Auth = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Token = conf.OAuth2.Issuer
				conf.OAuth2.Validate.Expression = "user.username == 'userinfo-user'"

				return conf
			}(),
			user: oauth2types.UserInfo{Username: "userinfo-user"},
		},
		{
			name: "try access known key",
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Issuer = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
				conf.OAuth2.Endpoints.Discovery = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Auth = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Token = conf.OAuth2.Issuer
				conf.OAuth2.Validate.Expression = "token.claims.unknown == 'test-user'"

				return conf
			}(),
			state: state.State{
				Client: state.ClientIdentifier{
					CommonName: "test-client",
				},
				IPAddr: "127.0.0.1",
			},
			token: &idtoken.IDToken{
				IDTokenClaims: &idtoken.Claims{
					Claims: map[string]any{
						"preferred_username": "test-user",
					},
				},
			},
			user: oauth2types.UserInfo{Username: "test-client"},
			err:  "failed to evaluate CEL expression: no such key: unknown",
		},
		{
			name: "try safe access known key",
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Issuer = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
				conf.OAuth2.Endpoints.Discovery = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Auth = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Token = conf.OAuth2.Issuer
				conf.OAuth2.Validate.Expression = "has(token.claims.unknown) && token.claims.unknown == 'test-user'"

				return conf
			}(),
			state: state.State{
				Client: state.ClientIdentifier{
					CommonName: "test-client",
				},
				IPAddr: "127.0.0.1",
			},
			token: &idtoken.IDToken{
				IDTokenClaims: &idtoken.Claims{
					Claims: map[string]any{
						"preferred_username": "test-user",
					},
				},
			},
			user: oauth2types.UserInfo{Username: "test-client"},
			err:  "cel validation failed",
		},
		{
			name: "CEL expression evaluates to true",
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Issuer = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
				conf.OAuth2.Endpoints.Discovery = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Auth = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Token = conf.OAuth2.Issuer
				conf.OAuth2.Validate.Expression = "openvpn.commonName == token.claims.preferred_username"

				return conf
			}(),
			state: state.State{
				Client: state.ClientIdentifier{
					CommonName: "test-client",
				},
				IPAddr: "127.0.0.1",
			},
			token: &idtoken.IDToken{
				IDTokenClaims: &idtoken.Claims{
					Claims: map[string]any{
						"preferred_username": "test-client",
					},
				},
			},
			user: oauth2types.UserInfo{Username: "test-client"},
		},
		{
			name: "CEL expression evaluates to false",
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Issuer = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
				conf.OAuth2.Endpoints.Discovery = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Auth = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Token = conf.OAuth2.Issuer
				conf.OAuth2.Validate.Expression = "openvpn.commonName != token.claims.preferred_username"

				return conf
			}(),
			state: state.State{
				Client: state.ClientIdentifier{
					CommonName: "test-client",
				},
				IPAddr: "127.0.0.1",
			},
			token: &idtoken.IDToken{
				IDTokenClaims: &idtoken.Claims{
					Claims: map[string]any{
						"preferred_username": "test-client",
					},
				},
			},
			user: oauth2types.UserInfo{Username: "test-client"},
			err:  oauth2.ErrCELValidationFailed.Error(),
		},
		{
			name: "CEL expression evaluates to string",
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Issuer = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
				conf.OAuth2.Endpoints.Discovery = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Auth = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Token = conf.OAuth2.Issuer
				conf.OAuth2.Validate.Expression = "openvpn.commonName"

				return conf
			}(),
			state: state.State{
				Client: state.ClientIdentifier{
					CommonName: "test-client",
				},
				IPAddr: "127.0.0.1",
			},
			token: &idtoken.IDToken{
				IDTokenClaims: &idtoken.Claims{
					Claims: map[string]any{
						"preferred_username": "test-client",
					},
				},
			},
			user: oauth2types.UserInfo{Username: "test-client"},
			err:  "cel expression did not evaluate to a boolean value",
		},
		{
			name: "CEL expression with lowerAscii",
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Issuer = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
				conf.OAuth2.Endpoints.Discovery = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Auth = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Token = conf.OAuth2.Issuer
				conf.OAuth2.Validate.Expression = "openvpn.commonName.lowerAscii() == string(token.claims.preferred_username).lowerAscii()"

				return conf
			}(),
			state: state.State{
				Client: state.ClientIdentifier{
					CommonName: "Test-Client",
				},
				IPAddr: "127.0.0.1",
			},
			token: &idtoken.IDToken{
				IDTokenClaims: &idtoken.Claims{
					Claims: map[string]any{
						"preferred_username": "test-client",
					},
				},
			},
			user: oauth2types.UserInfo{Username: "test-client"},
		},
		{
			name: "CEL expression with token IP address",
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Issuer = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
				conf.OAuth2.Endpoints.Discovery = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Auth = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Token = conf.OAuth2.Issuer
				conf.OAuth2.Validate.Expression = "openvpn.ip == token.ip"

				return conf
			}(),
			state: state.State{
				Client: state.ClientIdentifier{
					CommonName: "test-client",
				},
				IPAddr: "127.0.0.1",
			},
			token: &idtoken.IDToken{
				IDTokenClaims: &idtoken.Claims{
					Claims: map[string]any{
						"preferred_username": "test-client",
					},
					IPAddr: "127.0.0.1",
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			provider, err := generic.NewProvider(t.Context(), &tc.conf, http.DefaultClient)
			require.NoError(t, err)

			oAuth2Client, err := oauth2.New(t.Context(), slog.New(slog.DiscardHandler), &tc.conf, http.DefaultClient, testsuite.NewFakeStorage(), testsuite.Cipher, provider, testsuite.NewFakeOpenVPNClient())
			if tc.conf.OAuth2.Validate.Expression == "-" {
				require.ErrorContains(t, err, "failed to compile CEL expression:")

				return
			}

			require.NoError(t, err)

			err = oAuth2Client.CheckIdentityCEL(oauth2.CELAuthModeInteractive, tc.state, tc.token, tc.user)
			if tc.err != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.err)

				return
			}

			require.NoError(t, err)
		})
	}
}
