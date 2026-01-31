package generic

import (
	"context"
	"net/http"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
)

const Name = "generic"

type Provider struct {
	Conf config.Config
}

// NewProvider creates a new generic provider from the supplied configuration.
// The http.Client argument is ignored because the provider uses the global
// client from the oauth2 package.
func NewProvider(_ context.Context, conf config.Config, _ *http.Client) (*Provider, error) {
	return &Provider{
		Conf: conf,
	}, nil
}

// GetName returns the identifier of this provider implementation.
func (p Provider) GetName() string {
	return Name
}
