package generic

import (
	"context"
	"net/http"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
)

const Name = "generic"

type Provider struct {
	Conf *config.Config
}

func NewProvider(_ context.Context, conf *config.Config, _ *http.Client) (*Provider, error) {
	return &Provider{
		Conf: conf,
	}, nil
}

func (p *Provider) GetName() string {
	return Name
}
