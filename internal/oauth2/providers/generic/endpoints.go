package generic

import (
	"errors"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"golang.org/x/oauth2"
)

func (p *Provider) GetEndpoints(conf config.Config) (*oauth2.Endpoint, error) {
	if utils.IsUrlEmpty(conf.Oauth2.Endpoints.Token) && utils.IsUrlEmpty(conf.Oauth2.Endpoints.Auth) {
		return nil, nil
	}

	if (!utils.IsUrlEmpty(conf.Oauth2.Endpoints.Token) && utils.IsUrlEmpty(conf.Oauth2.Endpoints.Auth)) ||
		(utils.IsUrlEmpty(conf.Oauth2.Endpoints.Token) && !utils.IsUrlEmpty(conf.Oauth2.Endpoints.Auth)) {
		return nil, errors.New("both oauth2.endpoints.tokenUrl and oauth2.endpoints.authUrl are required")
	}

	return &oauth2.Endpoint{
		AuthURL:  conf.Oauth2.Endpoints.Auth.String(),
		TokenURL: conf.Oauth2.Endpoints.Token.String(),
	}, nil
}
