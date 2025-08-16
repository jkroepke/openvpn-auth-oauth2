package authentik_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/authentik"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProvider_GetName(t *testing.T) {
	t.Parallel()

	conf := config.Config{
		OAuth2: config.OAuth2{
			Issuer: types.URL{URL: &url.URL{Scheme: "https", Host: "auth.example.com"}},
		},
	}

	provider, err := authentik.NewProvider(context.Background(), conf, http.DefaultClient)
	require.NoError(t, err)

	assert.Equal(t, "authentik", provider.GetName())
}