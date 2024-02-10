package google

import (
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"golang.org/x/oauth2"
)

// GetProviderConfig implements the [github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2.Provider] interface.
func (p *Provider) GetProviderConfig(conf config.Config) (types.ProviderConfig, error) {
	providerConfig, err := p.Provider.GetProviderConfig(conf)
	if err != nil {
		return types.ProviderConfig{}, err //nolint:wrapcheck
	}

	if conf.OAuth2.Refresh.Enabled {
		// Enable offline access to getAPI a refresh token
		providerConfig.AuthCodeOptions = []oauth2.AuthCodeOption{oauth2.AccessTypeOffline}
	}

	providerConfig.Scopes = []string{types.ScopeEmail, types.ScopeProfile, types.ScopeOpenID}

	return providerConfig, nil
}
