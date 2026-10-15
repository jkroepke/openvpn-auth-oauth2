package oauth2

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"golang.org/x/oauth2"
)

// tokenEndpoint records client credentials requests and answers with a token.
type tokenEndpoint struct {
	server   *httptest.Server
	requests []url.Values
	mu       sync.Mutex
}

func newTokenEndpoint(t *testing.T) *tokenEndpoint {
	t.Helper()

	endpoint := &tokenEndpoint{}
	endpoint.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)

			return
		}

		endpoint.mu.Lock()
		endpoint.requests = append(endpoint.requests, r.PostForm)
		endpoint.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "ssf-access-token", "token_type": "Bearer", "expires_in": 300})
	}))
	t.Cleanup(endpoint.server.Close)

	return endpoint
}

func (e *tokenEndpoint) lastRequest() url.Values {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.requests[len(e.requests)-1]
}

func TestClientCredentialsTokenWithSecret(t *testing.T) {
	t.Parallel()

	endpoint := newTokenEndpoint(t)

	relyingParty, err := rp.NewRelyingPartyOAuth(&oauth2.Config{
		ClientID:     "vpn",
		ClientSecret: "secret",
		Endpoint:     oauth2.Endpoint{TokenURL: endpoint.server.URL, AuthStyle: oauth2.AuthStyleInParams},
		Scopes:       []string{"openid", "profile"},
	}, rp.WithHTTPClient(endpoint.server.Client()), rp.WithAuthStyle(oauth2.AuthStyleInParams))
	require.NoError(t, err)

	client := &Client{relyingParty: relyingParty}

	token, err := client.ClientCredentialsToken(t.Context(), "ssf.read")
	require.NoError(t, err)
	assert.Equal(t, "ssf-access-token", token.AccessToken)

	request := endpoint.lastRequest()
	assert.Equal(t, "client_credentials", request.Get("grant_type"))
	assert.Equal(t, "ssf.read", request.Get("scope"), "the login scopes are not requested")
	assert.Equal(t, "vpn", request.Get("client_id"))
	assert.Equal(t, "secret", request.Get("client_secret"))
	assert.Empty(t, request.Get("client_assertion"))
}

func TestClientCredentialsTokenWithPrivateKey(t *testing.T) {
	t.Parallel()

	endpoint := newTokenEndpoint(t)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	relyingParty, err := rp.NewRelyingPartyOAuth(&oauth2.Config{
		ClientID: "vpn",
		Endpoint: oauth2.Endpoint{TokenURL: endpoint.server.URL, AuthStyle: oauth2.AuthStyleInParams},
	}, rp.WithHTTPClient(endpoint.server.Client()), rp.WithJWTProfile(rp.SignerFromKeyAndKeyID(keyPEM, "key-1")))
	require.NoError(t, err)

	client := &Client{relyingParty: relyingParty}

	_, err = client.ClientCredentialsToken(t.Context(), "ssf.read")
	require.NoError(t, err)

	request := endpoint.lastRequest()
	assert.Equal(t, "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", request.Get("client_assertion_type"))
	assert.NotEmpty(t, request.Get("client_assertion"))
	assert.Empty(t, request.Get("client_secret"))
}

func TestClientCredentialsTokenError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"unauthorized_client"}`, http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)

	relyingParty, err := rp.NewRelyingPartyOAuth(&oauth2.Config{
		ClientID: "vpn",
		Endpoint: oauth2.Endpoint{TokenURL: server.URL},
	}, rp.WithHTTPClient(server.Client()))
	require.NoError(t, err)

	_, err = (&Client{relyingParty: relyingParty}).ClientCredentialsToken(t.Context(), "ssf.read")
	require.ErrorContains(t, err, "client credentials grant")
}
