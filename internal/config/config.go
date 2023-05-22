package config

import (
	"net/url"

	"github.com/caarlos0/env/v8"
)

const (
	ProviderGeneric = "generic"
	ProviderAzureAd = "azuread"
)

type Config struct {
	Provider     string   `env:"OAUTH2_PROVIDER" envDefault:"generic"`
	AuthTimeout  int      `env:"OAUTH2_AUTH_TIMEOUT" envDefault:"300"`
	UrlHelper    url.URL  `env:"OAUTH2_URL_HELPER" envDefault:"https://jkroepke.github.io/openvpn-auth-oauth2/"`
	CnBypassAuth []string `env:"OAUTH2_CN_BYPASS_AUTH" envDefault:"" envSeparator:","`
}

func LoadConfig() (Config, error) {
	conf := Config{}

	// Load env vars.
	if err := env.Parse(&conf); err != nil {
		return conf, err
	}

	return conf, nil
}
