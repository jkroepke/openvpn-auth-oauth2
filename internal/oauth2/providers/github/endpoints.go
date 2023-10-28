package github

import (
	"errors"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

func (p *Provider) GetEndpoints(conf config.Config) (oauth2.Endpoint, error) {
	if utils.IsURLEmpty(conf.OAuth2.Endpoints.Token) && utils.IsURLEmpty(conf.OAuth2.Endpoints.Auth) {
		return github.Endpoint, nil
	}

	if (!utils.IsURLEmpty(conf.OAuth2.Endpoints.Token) && utils.IsURLEmpty(conf.OAuth2.Endpoints.Auth)) ||
		(utils.IsURLEmpty(conf.OAuth2.Endpoints.Token) && !utils.IsURLEmpty(conf.OAuth2.Endpoints.Auth)) {
		return oauth2.Endpoint{}, errors.New("both oauth2.endpoints.tokenUrl and oauth2.endpoints.authUrl are required")
	}

	return oauth2.Endpoint{
		AuthURL:  conf.OAuth2.Endpoints.Auth.String(),
		TokenURL: conf.OAuth2.Endpoints.Token.String(),
	}, nil
}
