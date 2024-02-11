package google

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

// getHTTPClient returns a JWT config for the Google API.
// If a service account config is provided in the configuration, it will be used.
func getHTTPClient(ctx context.Context, conf config.Config) (*http.Client, error) {
	var (
		err error
		ts  oauth2.TokenSource
	)

	if conf.Provider.Google.ServiceAccountConfig != "" {
		ts, err = getTokenSourceByServiceAccountConfig(ctx, conf)
	} else {
		ts, err = getTokenSourceByDefaultApplicationCredentials(ctx, conf)
	}

	if err != nil {
		return nil, err
	}

	return oauth2.NewClient(ctx, ts), nil
}

func getTokenSourceByDefaultApplicationCredentials(ctx context.Context, conf config.Config) (oauth2.TokenSource, error) {
	credentials, err := google.FindDefaultCredentials(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch application default credentials: %w", err)
	}

	credentialsConfig := impersonate.CredentialsConfig{
		Scopes:   []string{AdminDirectoryGroupReadonlyScope},
		Lifetime: 300 * time.Second,
	}

	if len(conf.Provider.Google.ImpersonateAccount) > 0 {
		credentialsConfig.TargetPrincipal = conf.Provider.Google.ImpersonateAccount
	}

	if len(conf.Provider.Google.AdminEmail) > 0 {
		credentialsConfig.Subject = conf.Provider.Google.AdminEmail
	}

	ts, err := impersonate.CredentialsTokenSource(ctx, credentialsConfig, option.WithCredentials(credentials))
	if err != nil {
		return nil, fmt.Errorf("CredentialsTokenSource error: %w", err)
	}

	return ts, nil
}

func getTokenSourceByServiceAccountConfig(ctx context.Context, conf config.Config) (oauth2.TokenSource, error) {
	credentials, err := google.CredentialsFromJSON(ctx, []byte(conf.Provider.Google.ServiceAccountConfig))
	if err != nil {
		return nil, fmt.Errorf("error reading credentials: %w", err)
	}

	jwtConfig, err := google.JWTConfigFromJSON(credentials.JSON, AdminDirectoryGroupReadonlyScope)
	if err != nil {
		return nil, fmt.Errorf("unable to parse client secret file to config: %w", err)
	}

	if len(conf.Provider.Google.AdminEmail) > 0 {
		jwtConfig.Subject = conf.Provider.Google.AdminEmail
	}

	return jwtConfig.TokenSource(ctx), err
}
