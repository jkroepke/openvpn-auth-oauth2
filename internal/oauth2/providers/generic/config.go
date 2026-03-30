package generic

import (
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	gooauth2 "golang.org/x/oauth2"
)

// GetProviderConfig implements the [github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2.Provider] interface.
func (p Provider) GetProviderConfig() (types.ProviderConfig, error) {
	scopes := []string{types.ScopeOpenID, types.ScopeProfile, types.ScopeOfflineAccess}

	if (p.Conf.OAuth2.Endpoints.Token == nil || p.Conf.OAuth2.Endpoints.Token.String() == "") &&
		(p.Conf.OAuth2.Endpoints.Auth == nil || p.Conf.OAuth2.Endpoints.Auth.String() == "") {
		return types.ProviderConfig{Scopes: scopes}, nil
	}
	if (p.Conf.OAuth2.Endpoints.Token == nil || p.Conf.OAuth2.Endpoints.Token.String() == "") ||
		(p.Conf.OAuth2.Endpoints.Auth == nil || p.Conf.OAuth2.Endpoints.Auth.String() == "") {
		return types.ProviderConfig{}, oauth2.ErrAuthAndTokenEndpointRequired
	}

	return types.ProviderConfig{
		Endpoint: gooauth2.Endpoint{
			AuthURL:  p.Conf.OAuth2.Endpoints.Auth.String(),
			TokenURL: p.Conf.OAuth2.Endpoints.Token.String(),
		},
		Scopes: scopes,
	}, nil
}
