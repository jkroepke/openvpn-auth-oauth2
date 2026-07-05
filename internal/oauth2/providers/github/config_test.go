package github_test

import (
	"net/http"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/providers/github"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2/endpoints"
)

func TestProviderBasics(t *testing.T) {
	t.Parallel()

	provider, err := github.NewProvider(t.Context(), new(config.Defaults), http.DefaultClient)
	require.NoError(t, err)
	require.Equal(t, github.Name, provider.GetName())

	providerConfig, err := provider.GetProviderConfig()
	require.NoError(t, err)
	require.Equal(t, []string{"user:email", "read:org"}, providerConfig.Scopes)
	require.Equal(t, endpoints.GitHub, providerConfig.Endpoint)
}
