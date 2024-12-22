package generic

import (
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	oauth3 "github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"golang.org/x/oauth2"
)

// GetProviderConfig implements the [github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2.Provider] interface.
func (p Provider) GetProviderConfig() (types.ProviderConfig, error) {
	scopes := []string{types.ScopeOpenID, types.ScopeProfile, types.ScopeOfflineAccess}

	if config.IsURLEmpty(p.Conf.OAuth2.Endpoints.Token) && config.IsURLEmpty(p.Conf.OAuth2.Endpoints.Auth) {
		return types.ProviderConfig{Scopes: scopes}, nil
	}

	if config.IsURLEmpty(p.Conf.OAuth2.Endpoints.Auth) || config.IsURLEmpty(p.Conf.OAuth2.Endpoints.Token) {
		return types.ProviderConfig{}, oauth3.ErrAuthAndTokenEndpointRequired
	}

	return types.ProviderConfig{
		Endpoint: oauth2.Endpoint{
			AuthURL:  p.Conf.OAuth2.Endpoints.Auth.String(),
			TokenURL: p.Conf.OAuth2.Endpoints.Token.String(),
		},
		Scopes: scopes,
	}, nil
}
