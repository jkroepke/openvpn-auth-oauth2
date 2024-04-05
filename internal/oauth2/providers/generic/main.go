package generic

import (
	"context"
	"net/http"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
)

const Name = "generic"

type Provider struct {
	Conf config.Config
	rp   rp.RelyingParty
}

func NewProvider(_ context.Context, conf config.Config, _ *http.Client) (*Provider, error) {
	return &Provider{
		Conf: conf,
	}, nil
}

func (p *Provider) GetName() string {
	return Name
}
