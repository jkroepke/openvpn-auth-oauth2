package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/oidc"
)

type Provider struct {
	*oidc.Provider
}

func NewProvider(conf *config.Config) *Provider {
	return &Provider{
		Provider: oidc.NewProvider(conf),
	}
}

func requestApi[T any](ctx context.Context, accessToken string, path string) (*T, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com"+path, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Add("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	} else if resp.StatusCode != 200 {
		return nil, fmt.Errorf("error from github api %s, http status code: %d", path, resp.StatusCode)
	}

	defer resp.Body.Close()

	var t T
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		return nil, err
	}

	return &t, nil
}
