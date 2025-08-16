package authentik

import (
	"context"
	"fmt"
	"net/http"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
)

const Name = "authentik"

type Provider struct {
	*generic.Provider
}

// NewProvider instantiates the Authentik provider using the generic implementation
// as a base.
func NewProvider(ctx context.Context, conf config.Config, client *http.Client) (*Provider, error) {
	provider, err := generic.NewProvider(ctx, conf, client)
	if err != nil {
		return nil, fmt.Errorf("error creating generic provider: %w", err)
	}

	return &Provider{
		Provider: provider,
	}, nil
}

// GetName returns the provider name used in configuration and logging.
func (p Provider) GetName() string {
	return Name
}