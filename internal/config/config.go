package config

import (
	"github.com/caarlos0/env/v8"
)

const (
	ProviderGeneric = "generic"
	ProviderAzureAd = "azuread"
)

type Config struct {
	Provider     string   `env:"OPENVPN_OAUTH2_PROVIDER" envDefault:"generic"`
	CnBypassAuth []string `env:"OPENVPN_OAUTH2_CN_BYPASS_AUTH" envDefault:"" envSeparator:","`
}

func LoadConfig() (Config, error) {
	conf := Config{}

	// Load env vars.
	if err := env.Parse(&conf); err != nil {
		return conf, err
	}

	return conf, nil
}
