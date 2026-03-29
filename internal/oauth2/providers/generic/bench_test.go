package generic_test

import (
	"context"
	"log/slog"
	"net/http"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	oauth2types "github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func BenchmarkGetUser(b *testing.B) {
	ctx := context.Background()
	logger := slog.New(slog.DiscardHandler)

	for _, tc := range []struct {
		name  string
		conf  config.Config
		token idtoken.IDToken
	}{
		{
			name: "default-username-claim",
			conf: config.Defaults,
			token: &oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					Claims: map[string]any{
						"preferred_username": "username",
					},
					TokenClaims: oidc.TokenClaims{Subject: "subject"},
				},
			},
		},
		{
			name: "groups-string-slice",
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Validate.Groups = []string{"group"}

				return conf
			}(),
			token: &oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					Claims: map[string]any{
						"preferred_username": "username",
						"groups":             []string{"group1", "group2"},
					},
					TokenClaims: oidc.TokenClaims{Subject: "subject"},
				},
			},
		},
		{
			name: "groups-any-slice",
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Validate.Groups = []string{"group"}

				return conf
			}(),
			token: &oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					Claims: map[string]any{
						"preferred_username": "username",
						"groups":             []any{"group1", "group2"},
					},
					TokenClaims: oidc.TokenClaims{Subject: "subject"},
				},
			},
		},
		{
			name: "username-cel",
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.OpenVPNUsernameClaim = ""
				conf.OAuth2.OpenVPNUsernameCEL = "string(oauth2TokenClaims.groups[0])"

				return conf
			}(),
			token: &oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{
					Claims: map[string]any{
						"groups": []any{"group1", "group2"},
					},
					TokenClaims: oidc.TokenClaims{Subject: "subject"},
				},
			},
		},
	} {
		b.Run(tc.name, func(b *testing.B) {
			provider, err := generic.NewProvider(ctx, tc.conf, http.DefaultClient)
			require.NoError(b, err)

			var user oauth2types.UserInfo

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				user, err = provider.GetUser(ctx, logger, tc.token, nil)
				if err != nil {
					b.Fatal(err)
				}
			}

			_ = user
		})
	}
}
