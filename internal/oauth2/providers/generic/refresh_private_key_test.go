package generic_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/providers/generic"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// tokenEndpoint records the form of every request to /token and answers
// invalid_grant: the test is about how the client authenticates, not about
// the tokens.
type tokenEndpoint struct {
	mu    sync.Mutex
	forms []url.Values
}

func (e *tokenEndpoint) handler(issuer *string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                *issuer,
			"authorization_endpoint":                *issuer + "/auth",
			"token_endpoint":                        *issuer + "/token",
			"jwks_uri":                              *issuer + "/jwks",
			"token_endpoint_auth_methods_supported": []string{"private_key_jwt"},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()

		e.mu.Lock()
		e.forms = append(e.forms, r.PostForm)
		e.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	})

	return mux
}

func assertionClaims(t *testing.T, assertion string) map[string]any {
	t.Helper()

	parts := strings.Split(assertion, ".")
	require.Len(t, parts, 3)

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))

	return claims
}

func TestRefreshWithPrivateKeySendsClientAssertion(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	var issuer string

	endpoint := &tokenEndpoint{}
	server := httptest.NewServer(endpoint.handler(&issuer))
	t.Cleanup(server.Close)
	issuer = server.URL

	relyingParty, err := rp.NewRelyingPartyOIDC(t.Context(), issuer, "vpn-client", "", "http://localhost/callback",
		[]string{oidc.ScopeOpenID}, rp.WithJWTProfile(rp.SignerFromKeyAndKeyID(keyPEM, "kid-1")))
	require.NoError(t, err)

	conf := config.Defaults
	provider, err := generic.NewProvider(t.Context(), &conf, http.DefaultClient)
	require.NoError(t, err)

	for range 2 {
		_, err = provider.Refresh(t.Context(), relyingParty, "refresh-token")
		require.Error(t, err)
	}

	require.Len(t, endpoint.forms, 2)

	jtis := map[string]bool{}

	for _, form := range endpoint.forms {
		require.Equal(t, oidc.ClientAssertionTypeJWTAssertion, form.Get("client_assertion_type"))
		require.Empty(t, form.Get("client_secret"))
		require.Equal(t, "refresh-token", form.Get("refresh_token"))

		claims := assertionClaims(t, form.Get("client_assertion"))
		require.Equal(t, "vpn-client", claims["iss"])
		require.Equal(t, "vpn-client", claims["sub"])
		require.Equal(t, []any{issuer}, claims["aud"], "the issuer must be the only audience")
		jti, ok := claims["jti"].(string)
		require.True(t, ok, "jti must be a string")
		require.NotEmpty(t, jti)

		jtis[jti] = true
	}

	require.Len(t, jtis, 2, "every refresh must sign a new assertion")
}

func TestRefreshWithoutPrivateKeySendsClientSecret(t *testing.T) {
	t.Parallel()

	var issuer string

	endpoint := &tokenEndpoint{}
	server := httptest.NewServer(endpoint.handler(&issuer))
	t.Cleanup(server.Close)
	issuer = server.URL

	relyingParty, err := rp.NewRelyingPartyOIDC(t.Context(), issuer, "vpn-client", "secret",
		"http://localhost/callback", []string{oidc.ScopeOpenID})
	require.NoError(t, err)

	conf := config.Defaults
	provider, err := generic.NewProvider(t.Context(), &conf, http.DefaultClient)
	require.NoError(t, err)

	_, err = provider.Refresh(t.Context(), relyingParty, "refresh-token")
	require.Error(t, err)

	require.Len(t, endpoint.forms, 1)
	require.Empty(t, endpoint.forms[0].Get("client_assertion"))
}
