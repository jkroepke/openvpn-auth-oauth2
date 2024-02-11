package generic

import (
	"errors"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"golang.org/x/oauth2"
)

// GetProviderConfig implements the [github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2.Provider] interface.
func (p *Provider) GetProviderConfig(conf config.Config) (types.ProviderConfig, error) {
	scopes := []string{types.ScopeOpenID, types.ScopeProfile, types.ScopeOfflineAccess}

	if config.IsURLEmpty(conf.OAuth2.Endpoints.Token) && config.IsURLEmpty(conf.OAuth2.Endpoints.Auth) {
		return types.ProviderConfig{Scopes: scopes}, nil
	}

	if config.IsURLEmpty(conf.OAuth2.Endpoints.Auth) || config.IsURLEmpty(conf.OAuth2.Endpoints.Token) {
		return types.ProviderConfig{}, errors.New("both oauth2.endpoints.tokenUrl and oauth2.endpoints.authUrl are required")
	}

	return types.ProviderConfig{
		Endpoint: oauth2.Endpoint{
			AuthURL:  conf.OAuth2.Endpoints.Auth.String(),
			TokenURL: conf.OAuth2.Endpoints.Token.String(),
		},
		Scopes: scopes,
	}, nil
}
