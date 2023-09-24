package oidc

import (
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
)

type Provider struct {
	Conf *config.Config
}

func NewProvider(conf *config.Config) *Provider {
	return &Provider{
		Conf: conf,
	}
}
