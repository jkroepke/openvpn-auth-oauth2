package google

import (
	"context"
	"fmt"
	"net/http"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
)

const Name = "google"

type Provider struct {
	*generic.Provider

	httpClient *http.Client
}

// NewProvider instantiates the Google provider using the generic implementation
// as a base. It wires in the HTTP client for REST API calls.
func NewProvider(ctx context.Context, conf config.Config, httpClient *http.Client) (*Provider, error) {
	provider, err := generic.NewProvider(ctx, conf, httpClient)
	if err != nil {
		return nil, fmt.Errorf("error creating generic provider: %w", err)
	}

	return &Provider{
		Provider:   provider,
		httpClient: httpClient,
	}, nil
}

// GetName returns the provider name used in configuration and logging.
func (p Provider) GetName() string {
	return Name
}
