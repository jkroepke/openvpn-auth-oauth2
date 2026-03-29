package oauth2 //nolint:testpackage

import (
	"net/http"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func BenchmarkGetAuthorizeParams(b *testing.B) {
	for _, tc := range []struct {
		name  string
		input string
	}{
		{
			name:  "single",
			input: "prompt=login",
		},
		{
			name:  "multiple",
			input: "prompt=login&audience=vpn&kc_idp_hint=google",
		},
	} {
		b.Run(tc.name, func(b *testing.B) {
			var params any

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				parsedParams, err := getAuthorizeParams(tc.input)
				if err != nil {
					b.Fatal(err)
				}

				params = parsedParams
			}

			_ = params
		})
	}
}

func BenchmarkCheckClientIPAddr(b *testing.B) {
	session := state.State{IPAddr: "127.0.0.1"}

	b.Run("direct", func(b *testing.B) {
		conf := config.Defaults
		req := &http.Request{RemoteAddr: "127.0.0.1:12345", Header: make(http.Header)}

		b.ReportAllocs()
		b.ResetTimer()

		for b.Loop() {
			if err := checkClientIPAddr(req, conf, session); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("proxy-headers", func(b *testing.B) {
		conf := config.Defaults
		conf.HTTP.EnableProxyHeaders = true

		req := &http.Request{RemoteAddr: "10.0.0.1:12345", Header: http.Header{"X-Forwarded-For": []string{"127.0.0.1, 10.0.0.1"}}}

		b.ReportAllocs()
		b.ResetTimer()

		for b.Loop() {
			if err := checkClientIPAddr(req, conf, session); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkCheckTokenCEL(b *testing.B) {
	for _, tc := range []struct {
		name       string
		expression string
		state      state.State
		token      idtoken.IDToken
	}{
		{
			name:       "equality",
			expression: "openVPNUserCommonName == oauth2TokenClaims.preferred_username",
			state: state.State{
				Client: state.ClientIdentifier{CommonName: "test-client"},
				IPAddr: "127.0.0.1",
			},
			token: &oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{Claims: map[string]any{"preferred_username": "test-client"}},
			},
		},
		{
			name:       "lower-ascii",
			expression: "openVPNUserCommonName.lowerAscii() == string(oauth2TokenClaims.preferred_username).lowerAscii()",
			state: state.State{
				Client: state.ClientIdentifier{CommonName: "Test-Client"},
				IPAddr: "127.0.0.1",
			},
			token: &oidc.Tokens[*idtoken.Claims]{
				IDTokenClaims: &idtoken.Claims{Claims: map[string]any{"preferred_username": "test-client"}},
			},
		},
	} {
		b.Run(tc.name, func(b *testing.B) {
			conf := config.Defaults
			conf.OAuth2.Validate.CEL = tc.expression

			client := &Client{conf: conf}
			require.NoError(b, client.initializeCELValidation())

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				if err := client.CheckTokenCEL(CELAuthModeInteractive, tc.state, tc.token); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
