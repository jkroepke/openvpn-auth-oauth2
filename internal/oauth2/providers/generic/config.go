package generic

import (
	oauth3 "github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"golang.org/x/oauth2"
)

// GetProviderConfig implements the [github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2.Provider] interface.
func (p Provider) GetProviderConfig() (types.ProviderConfig, error) {
	scopes := []string{types.ScopeOpenID, types.ScopeProfile, types.ScopeOfflineAccess}

	if p.Conf.OAuth2.Endpoints.Token.IsEmpty() && p.Conf.OAuth2.Endpoints.Auth.IsEmpty() {
		return types.ProviderConfig{Scopes: scopes}, nil
	}

	if p.Conf.OAuth2.Endpoints.Auth.IsEmpty() || p.Conf.OAuth2.Endpoints.Token.IsEmpty() {
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
