package google

import (
	"slices"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"golang.org/x/oauth2"
)

// GetProviderConfig implements the [github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2.Provider] interface.
func (p Provider) GetProviderConfig() (types.ProviderConfig, error) {
	providerConfig, err := p.Provider.GetProviderConfig()
	if err != nil {
		return types.ProviderConfig{}, err //nolint:wrapcheck
	}

	if p.Conf.OAuth2.Refresh.Enabled && p.Conf.OAuth2.Refresh.ValidateUser {
		// Enable offline access to api a refresh token
		providerConfig.AuthCodeOptions = []oauth2.AuthCodeOption{oauth2.AccessTypeOffline, oauth2.ApprovalForce}
	}

	providerConfig.Scopes = []string{types.ScopeEmail, types.ScopeProfile, types.ScopeOpenID}
	if len(p.Conf.OAuth2.Validate.Groups) > 0 {
		// Enable offline access to api a refresh token
		providerConfig.Scopes = append(providerConfig.Scopes, "https://www.googleapis.com/auth/cloud-identity.groups.readonly")
	}

	providerConfig.Scopes = slices.Compact(providerConfig.Scopes)

	return providerConfig, nil
}
