package github

import (
	"context"
	"fmt"
	"net/http"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
)

const Name = "github"

type Provider struct {
	*generic.Provider

	httpClient *http.Client
}

// NewProvider returns a GitHub provider configured with the given settings.
// It wraps the generic provider and adds the HTTP client for API lookups.
func NewProvider(ctx context.Context, conf config.Config, httpClient *http.Client) (Provider, error) {
	provider, err := generic.NewProvider(ctx, conf, httpClient)
	if err != nil {
		return Provider{}, fmt.Errorf("error creating generic provider: %w", err)
	}

	return Provider{
		Provider:   provider,
		httpClient: httpClient,
	}, nil
}

// GetName returns the provider name.
func (p Provider) GetName() string {
	return Name
}
