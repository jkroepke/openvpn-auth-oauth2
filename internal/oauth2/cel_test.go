package oauth2_test

import (
	"log/slog"
	"net/http"
	"net/url"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func TestCheckTokenCEL(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		conf  config.Config
		state state.State
		token idtoken.IDToken
		err   string
	}{
		{
			name: "no CEL expression configured",
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Issuer = &url.URL{Scheme: "http", Host: "localhost"}
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
				conf.OAuth2.Issuer = &url.URL{Scheme: "http", Host: "localhost"}
				conf.OAuth2.Endpoints.Discovery = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Auth = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Token = conf.OAuth2.Issuer
				conf.OAuth2.Validate.CEL = ""

				return conf
			}(),
		},
		{
			name: "invalid CEL expression configured",
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Issuer = &url.URL{Scheme: "http", Host: "localhost"}
				conf.OAuth2.Endpoints.Discovery = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Auth = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Token = conf.OAuth2.Issuer
				conf.OAuth2.Validate.CEL = "-"

				return conf
			}(),
		},
		{
			name: "missing ID token claims",
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Issuer = &url.URL{Scheme: "http", Host: "localhost"}
				conf.OAuth2.Endpoints.Discovery = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Auth = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Token = conf.OAuth2.Issuer
				conf.OAuth2.Validate.CEL = "true"

				return conf
			}(),
			err: oauth2.ErrNoIDTokenAvailable.Error(),
		},
		{
			name: "try access known key",
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Issuer = &url.URL{Scheme: "http", Host: "localhost"}
				conf.OAuth2.Endpoints.Discovery = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Auth = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Token = conf.OAuth2.Issuer
				conf.OAuth2.Validate.CEL = "oauth2TokenClaims.unknown == 'test-user'"

				return conf
			}(),
			state: state.State{
				Client: state.ClientIdentifier{
					CommonName: "test-client",
				},
				IPAddr: "127.0.0.1",
			},
			token: &oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					Claims: map[string]any{
						"preferred_username": "test-user",
					},
				},
			},
			err: "failed to evaluate CEL expression: no such key: unknown",
		},
		{
			name: "try safe access known key",
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Issuer = &url.URL{Scheme: "http", Host: "localhost"}
				conf.OAuth2.Endpoints.Discovery = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Auth = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Token = conf.OAuth2.Issuer
				conf.OAuth2.Validate.CEL = "has(oauth2TokenClaims.unknown) && oauth2TokenClaims.unknown == 'test-user'"

				return conf
			}(),
			state: state.State{
				Client: state.ClientIdentifier{
					CommonName: "test-client",
				},
				IPAddr: "127.0.0.1",
			},
			token: &oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					Claims: map[string]any{
						"preferred_username": "test-user",
					},
				},
			},
			err: "cel validation failed",
		},
		{
			name: "CEL expression evaluates to true",
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Issuer = &url.URL{Scheme: "http", Host: "localhost"}
				conf.OAuth2.Endpoints.Discovery = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Auth = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Token = conf.OAuth2.Issuer
				conf.OAuth2.Validate.CEL = "openVPNUserCommonName == oauth2TokenClaims.preferred_username"

				return conf
			}(),
			state: state.State{
				Client: state.ClientIdentifier{
					CommonName: "test-client",
				},
				IPAddr: "127.0.0.1",
			},
			token: &oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					Claims: map[string]any{
						"preferred_username": "test-client",
					},
				},
			},
		},
		{
			name: "CEL expression evaluates to false",
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Issuer = &url.URL{Scheme: "http", Host: "localhost"}
				conf.OAuth2.Endpoints.Discovery = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Auth = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Token = conf.OAuth2.Issuer
				conf.OAuth2.Validate.CEL = "openVPNUserCommonName != oauth2TokenClaims.preferred_username"

				return conf
			}(),
			state: state.State{
				Client: state.ClientIdentifier{
					CommonName: "test-client",
				},
				IPAddr: "127.0.0.1",
			},
			token: &oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					Claims: map[string]any{
						"preferred_username": "test-client",
					},
				},
			},
			err: oauth2.ErrCELValidationFailed.Error(),
		},
		{
			name: "CEL expression evaluates to string",
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Issuer = &url.URL{Scheme: "http", Host: "localhost"}
				conf.OAuth2.Endpoints.Discovery = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Auth = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Token = conf.OAuth2.Issuer
				conf.OAuth2.Validate.CEL = "openVPNUserCommonName"

				return conf
			}(),
			state: state.State{
				Client: state.ClientIdentifier{
					CommonName: "test-client",
				},
				IPAddr: "127.0.0.1",
			},
			token: &oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					Claims: map[string]any{
						"preferred_username": "test-client",
					},
				},
			},
			err: "cel expression did not evaluate to a boolean value",
		},
		{
			name: "CEL expression with lowerAscii",
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Issuer = &url.URL{Scheme: "http", Host: "localhost"}
				conf.OAuth2.Endpoints.Discovery = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Auth = conf.OAuth2.Issuer
				conf.OAuth2.Endpoints.Token = conf.OAuth2.Issuer
				conf.OAuth2.Validate.CEL = "openVPNUserCommonName.lowerAscii() == string(oauth2TokenClaims.preferred_username).lowerAscii()"

				return conf
			}(),
			state: state.State{
				Client: state.ClientIdentifier{
					CommonName: "Test-Client",
				},
				IPAddr: "127.0.0.1",
			},
			token: &oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					Claims: map[string]any{
						"preferred_username": "test-client",
					},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			provider, err := generic.NewProvider(t.Context(), tc.conf, http.DefaultClient)
			require.NoError(t, err)

			oAuth2Client, err := oauth2.New(t.Context(), slog.New(slog.DiscardHandler), tc.conf, http.DefaultClient, testutils.NewFakeStorage(), provider, testutils.NewFakeOpenVPNClient())
			if tc.conf.OAuth2.Validate.CEL == "-" {
				require.ErrorContains(t, err, "failed to compile CEL expression:")

				return
			}

			require.NoError(t, err)

			err = oAuth2Client.CheckTokenCEL(oauth2.CELAuthModeInteractive, tc.state, tc.token)
			if tc.err != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tc.err)

				return
			}

			require.NoError(t, err)
		})
	}
}
