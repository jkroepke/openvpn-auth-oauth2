package google_test

import (
	"net/http"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/google"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/stretchr/testify/require"
)

func TestProviderBasics(t *testing.T) {
	t.Parallel()

	provider, err := google.NewProvider(t.Context(), new(config.Defaults), http.DefaultClient)
	require.NoError(t, err)
	require.Equal(t, google.Name, provider.GetName())

	providerConfig, err := provider.GetProviderConfig()
	require.NoError(t, err)
	require.Equal(t, []string{types.ScopeEmail, types.ScopeProfile, types.ScopeOpenID}, providerConfig.Scopes)
	require.Empty(t, providerConfig.AuthCodeOptions)
}

func TestGetProviderConfigWithRefreshValidation(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	conf.OAuth2.Refresh.Enabled = true
	conf.OAuth2.Refresh.ValidateUser = true

	provider, err := google.NewProvider(t.Context(), &conf, http.DefaultClient)
	require.NoError(t, err)

	providerConfig, err := provider.GetProviderConfig()
	require.NoError(t, err)
	require.Len(t, providerConfig.AuthCodeOptions, 2)
}

func TestGetProviderConfigWithGroupValidation(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	conf.OAuth2.Validate.Groups = []string{"group-id"}

	provider, err := google.NewProvider(t.Context(), &conf, http.DefaultClient)
	require.NoError(t, err)

	providerConfig, err := provider.GetProviderConfig()
	require.NoError(t, err)
	require.Contains(t, providerConfig.Scopes, "https://www.googleapis.com/auth/cloud-identity.groups.readonly")
}
