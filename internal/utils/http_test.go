package utils_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewUserAgentTransport(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.UserAgent()))
	}))

	server.Client().Transport = utils.NewUserAgentTransport(nil)

	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL, nil)

	require.NoError(t, err)

	resp, err := server.Client().Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, "openvpn-auth-oauth2", string(body))
}
