package utils_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewUserAgentTransport(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.UserAgent()))
	}))

	server.Client().Transport = utils.NewUserAgentTransport(nil)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL, nil)

	require.NoError(t, err)

	resp, err := server.Client().Do(req)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, resp.Body.Close())
	})

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, "openvpn-auth-oauth2", string(body))
}

func TestNewOAuth2HTTPClient(t *testing.T) {
	t.Parallel()

	client := utils.NewOAuth2HTTPClient(nil)

	require.NotNil(t, client.Transport)
	require.NotNil(t, client.CheckRedirect)
	assert.Equal(t, 30*time.Second, client.Timeout)
}

func TestCheckOAuth2ProviderRedirect(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name        string
		originalURL string
		redirectURL string
		expectedErr error
	}{
		{
			name:        "same host",
			originalURL: "https://provider.example.com/token",
			redirectURL: "https://provider.example.com/token-v2",
		},
		{
			name:        "http to https same host",
			originalURL: "http://provider.example.com/token",
			redirectURL: "https://provider.example.com/token",
		},
		{
			name:        "cross host",
			originalURL: "https://provider.example.com/token",
			redirectURL: "https://metadata.internal/token",
			expectedErr: utils.ErrOAuth2ProviderRedirectHost,
		},
		{
			name:        "subdomain",
			originalURL: "https://provider.example.com/token",
			redirectURL: "https://attacker.provider.example.com/token",
			expectedErr: utils.ErrOAuth2ProviderRedirectHost,
		},
		{
			name:        "https downgrade",
			originalURL: "https://provider.example.com/token",
			redirectURL: "http://provider.example.com/token",
			expectedErr: utils.ErrOAuth2ProviderRedirectDowngrade,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tc.redirectURL, nil)
			via := []*http.Request{httptest.NewRequestWithContext(t.Context(), http.MethodGet, tc.originalURL, nil)}

			err := utils.CheckOAuth2ProviderRedirect(req, via)

			if tc.expectedErr == nil {
				require.NoError(t, err)

				return
			}

			require.Error(t, err)
			assert.ErrorIs(t, err, tc.expectedErr)
		})
	}
}
