package providers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/github"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/google"
)

// New creates the OAuth2 provider implementation selected by configuration.
func New(ctx context.Context, conf *config.Config, httpClient *http.Client) (oauth2.Provider, error) {
	switch conf.OAuth2.Provider {
	case generic.Name:
		provider, err := generic.NewProvider(ctx, conf, httpClient)
		if err != nil {
			return nil, fmt.Errorf("generic provider: %w", err)
		}

		return provider, nil
	case github.Name:
		provider, err := github.NewProvider(ctx, conf, httpClient)
		if err != nil {
			return nil, fmt.Errorf("github provider: %w", err)
		}

		return provider, nil
	case google.Name:
		provider, err := google.NewProvider(ctx, conf, httpClient)
		if err != nil {
			return nil, fmt.Errorf("google provider: %w", err)
		}

		return provider, nil
	default:
		return nil, fmt.Errorf("unknown oauth2 provider: %s", conf.OAuth2.Provider)
	}
}
