package github

import (
	"errors"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// GetEndpoints implements the [github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2.Provider] interface.
// It returns the OAuth2 GitHub [github.Endpoint], since GitHub does not support OIDC discovery.
func (p *Provider) GetEndpoints(conf config.Config) (oauth2.Endpoint, error) {
	if config.IsURLEmpty(conf.OAuth2.Endpoints.Token) && config.IsURLEmpty(conf.OAuth2.Endpoints.Auth) {
		return github.Endpoint, nil
	}

	if (!config.IsURLEmpty(conf.OAuth2.Endpoints.Token) && config.IsURLEmpty(conf.OAuth2.Endpoints.Auth)) ||
		(config.IsURLEmpty(conf.OAuth2.Endpoints.Token) && !config.IsURLEmpty(conf.OAuth2.Endpoints.Auth)) {
		return oauth2.Endpoint{}, errors.New("both oauth2.endpoints.tokenUrl and oauth2.endpoints.authUrl are required")
	}

	return oauth2.Endpoint{
		AuthURL:  conf.OAuth2.Endpoints.Auth.String(),
		TokenURL: conf.OAuth2.Endpoints.Token.String(),
	}, nil
}
