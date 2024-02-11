package github

import (
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

// GetProviderConfig implements the [github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2.Provider] interface.
// It returns the OAuth2 GitHub [endpoints.GitHub], since GitHub does not support OIDC discovery.
func (p *Provider) GetProviderConfig(conf config.Config) (types.ProviderConfig, error) {
	providerConfig, err := p.Provider.GetProviderConfig(conf)
	if err != nil {
		return types.ProviderConfig{}, err //nolint:wrapcheck
	}

	providerConfig.Scopes = []string{"user:email", "read:org"}

	if providerConfig.Endpoint == (oauth2.Endpoint{}) {
		providerConfig.Endpoint = endpoints.GitHub
	}

	return providerConfig, nil
}
