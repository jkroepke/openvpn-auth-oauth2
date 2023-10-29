package generic

import (
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
)

const Name = "generic"

type Provider struct {
	Conf config.Config
}

func NewProvider(conf config.Config) *Provider {
	return &Provider{
		Conf: conf,
	}
}

func (p *Provider) GetName() string {
	return Name
}

func (p *Provider) GetDefaultScopes() []string {
	return []string{"openid", "profile"}
}
