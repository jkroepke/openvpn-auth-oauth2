package generic

import (
	"context"

	"github.com/caarlos0/env/v8"
)

type providerConfig struct {
	authority string   `env:"OAUTH_AZURE_AD_AUTHORITY" envDefault:"https://login.microsoftonline.com/${OAUTH_AZURE_AD_TENANT_ID}" envExpand:"true"`
	tenantId  string   `env:"OAUTH_AZURE_AD_TENANT_ID"`
	clientId  string   `env:"OAUTH_AZURE_AD_CLIENT_ID"`
	scopes    []string `env:"OAUTH_AZURE_AD_TOKEN_SCOPES" envSeparator:" "`

	matchUsernameClientCn   bool   `env:"OAUTH_AZURE_AD_MATCH_USERNAME_CLIENT_CN" envDefault:"true"`
	matchUsernameTokenField string `env:"OAUTH_AZURE_AD_MATCH_USERNAME_TOKEN_FIELD" envDefault:"PreferredUsername"`
	matchClientIp           bool   `env:"OAUTH_AZURE_AD_MATCH_CLIENT_IP" envDefault:"false"`
}

type Provider struct {
	*providerConfig
}

func New() (*Provider, error) {
	conf := &providerConfig{}

	if err := env.ParseWithOptions(&conf, env.Options{RequiredIfNoDef: true}); err != nil {
		return &Provider{}, err
	}

	return &Provider{
		providerConfig: conf,
	}, nil
}

func (p *Provider) StartAuthentication(_ context.Context) (string, error) {
	return "", nil
}

func (p *Provider) ValidateAuthentication(_ context.Context) error {
	return nil
}
