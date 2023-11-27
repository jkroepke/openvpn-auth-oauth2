package generic

import (
	"errors"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"golang.org/x/oauth2"
)

func (p *Provider) GetEndpoints(conf config.Config) (oauth2.Endpoint, error) {
	if config.IsURLEmpty(conf.OAuth2.Endpoints.Token) && config.IsURLEmpty(conf.OAuth2.Endpoints.Auth) {
		return oauth2.Endpoint{}, nil
	}

	if config.IsURLEmpty(conf.OAuth2.Endpoints.Auth) || config.IsURLEmpty(conf.OAuth2.Endpoints.Token) {
		return oauth2.Endpoint{}, errors.New("both oauth2.endpoints.tokenUrl and oauth2.endpoints.authUrl are required")
	}

	return oauth2.Endpoint{
		AuthURL:  conf.OAuth2.Endpoints.Auth.String(),
		TokenURL: conf.OAuth2.Endpoints.Token.String(),
	}, nil
}
