package generic_test

import (
	"net/http"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	configtypes "github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	oauth2internal "github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/stretchr/testify/require"
	gooauth2 "golang.org/x/oauth2"
)

func TestProviderBasics(t *testing.T) {
	t.Parallel()

	conf := config.Defaults

	provider, err := generic.NewProvider(t.Context(), &conf, http.DefaultClient)
	require.NoError(t, err)
	require.Equal(t, generic.Name, provider.GetName())

	providerConfig, err := provider.GetProviderConfig()
	require.NoError(t, err)
	require.Equal(t, []string{types.ScopeOpenID, types.ScopeProfile, types.ScopeOfflineAccess}, providerConfig.Scopes)
	require.Equal(t, gooauth2.Endpoint{}, providerConfig.Endpoint)
}

func TestGetProviderConfigCustomEndpoints(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	authURL, err := configtypes.NewURL("https://provider.example.com/auth")
	require.NoError(t, err)

	tokenURL, err := configtypes.NewURL("https://provider.example.com/token")
	require.NoError(t, err)

	conf.OAuth2.Endpoints.Auth = authURL
	conf.OAuth2.Endpoints.Token = tokenURL

	provider, err := generic.NewProvider(t.Context(), &conf, http.DefaultClient)
	require.NoError(t, err)

	providerConfig, err := provider.GetProviderConfig()
	require.NoError(t, err)
	require.Equal(t, "https://provider.example.com/auth", providerConfig.AuthURL)
	require.Equal(t, "https://provider.example.com/token", providerConfig.TokenURL)
}

func TestGetProviderConfigRequiresAuthAndTokenEndpoints(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	authURL, err := configtypes.NewURL("https://provider.example.com/auth")
	require.NoError(t, err)

	conf.OAuth2.Endpoints.Auth = authURL

	provider, err := generic.NewProvider(t.Context(), &conf, http.DefaultClient)
	require.NoError(t, err)

	providerConfig, err := provider.GetProviderConfig()
	require.ErrorIs(t, err, oauth2internal.ErrAuthAndTokenEndpointRequired)
	require.Empty(t, providerConfig)
}
