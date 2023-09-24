package github

import (
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/oidc"
)

type Provider struct {
	*oidc.Provider
}

func NewProvider(conf *config.Config) *Provider {
	return &Provider{
		Provider: oidc.NewProvider(conf),
	}
}
