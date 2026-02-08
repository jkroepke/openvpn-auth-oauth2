package generic

import (
	oauth3 "github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"golang.org/x/oauth2"
)

// GetProviderConfig implements the [github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2.Provider] interface.
func (p Provider) GetProviderConfig() (types.ProviderConfig, error) {
	scopes := []string{types.ScopeOpenID, types.ScopeProfile, types.ScopeOfflineAccess}

	tokenEmpty := p.Conf.OAuth2.Endpoints.Token == nil || (p.Conf.OAuth2.Endpoints.Token.Scheme == "" && p.Conf.OAuth2.Endpoints.Token.Host == "")
	authEmpty := p.Conf.OAuth2.Endpoints.Auth == nil || (p.Conf.OAuth2.Endpoints.Auth.Scheme == "" && p.Conf.OAuth2.Endpoints.Auth.Host == "")

	if tokenEmpty && authEmpty {
		return types.ProviderConfig{Scopes: scopes}, nil
	}

	if authEmpty || tokenEmpty {
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
