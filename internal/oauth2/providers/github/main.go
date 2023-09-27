package github

import (
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
)

const Name = "github"

type Provider struct {
	*generic.Provider
}

func NewProvider(conf *config.Config) *Provider {
	return &Provider{
		Provider: generic.NewProvider(conf),
	}
}

func (p *Provider) GetName() string {
	return Name
}
