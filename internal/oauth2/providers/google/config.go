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

	if conf.OAuth2.Refresh.Enabled && conf.OAuth2.Refresh.ValidateUser {
		// Enable offline access to api a refresh token
		providerConfig.AuthCodeOptions = []oauth2.AuthCodeOption{oauth2.AccessTypeOffline, oauth2.ApprovalForce}
	}

	providerConfig.Scopes = []string{types.ScopeEmail, types.ScopeProfile, types.ScopeOpenID}
	if len(conf.OAuth2.Validate.Groups) > 0 {
		// Enable offline access to api a refresh token
		providerConfig.Scopes = append(providerConfig.Scopes, "https://www.googleapis.com/auth/cloud-identity.groups.readonly")
	}

	return providerConfig, nil
}
