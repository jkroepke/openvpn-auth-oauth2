package google

import (
	"context"
	"fmt"
	"net/http"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const Name = "google"

type Provider struct {
	*generic.Provider
	httpClient *http.Client
}

func NewProvider(ctx context.Context, conf config.Config, httpClient *http.Client) (*Provider, error) {
	provider, err := generic.NewProvider(ctx, conf, httpClient)
	if err != nil {
		return nil, fmt.Errorf("error creating generic provider: %w", err)
	}

	httpClient, err = getHTTPClient(ctx, conf, httpClient)
	if err != nil {
		return nil, fmt.Errorf("error getting JWT config: %w", err)
	}

	return &Provider{
		Provider:   provider,
		httpClient: httpClient,
	}, nil
}

func (p *Provider) GetName() string {
	return Name
}

// getHTTPClient returns a JWT config for the Google API.
// If a service account config is provided in the configuration, it will be used.
func getHTTPClient(ctx context.Context, conf config.Config, httpClient *http.Client) (*http.Client, error) {
	var (
		err         error
		credentials *google.Credentials
	)

	if conf.Provider.Google.ServiceAccountConfig == "" {
		credentials, err = google.FindDefaultCredentials(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch application default credentials: %w", err)
		}
	} else {
		credentials, err = google.CredentialsFromJSON(ctx, []byte(conf.Provider.Google.ServiceAccountConfig))
		if err != nil {
			return nil, fmt.Errorf("error reading credentials: %w", err)
		}
	}

	jwtConfig, err := google.JWTConfigFromJSON(credentials.JSON, AdminDirectoryGroupReadonlyScope)
	if err != nil {
		return nil, fmt.Errorf("unable to parse client secret file to config: %w", err)
	}

	if len(conf.Provider.Google.AdminEmails) > 0 {
		jwtConfig.Subject = conf.Provider.Google.AdminEmails[0]
	}

	return jwtConfig.Client(context.WithValue(ctx, oauth2.HTTPClient, httpClient)), nil
}
