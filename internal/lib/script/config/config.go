package config

import (
	"net/url"

	commonConfig "github.com/jkroepke/openvpn-auth-oauth2/internal/config"

	"github.com/caarlos0/env/v8"
)

type Config struct {
	commonConfig.Config

	AuthTimeout int     `env:"OPENVPN_AUTH_OAUTH2_AUTH_TIMEOUT" envDefault:"300"`
	UrlHelper   url.URL `env:"OPENVPN_AUTH_OAUTH2_URL_HELPER" envDefault:"https://jkroepke.github.io/openvpn-auth-oauth2/"`
}

func LoadConfig() (Config, error) {
	conf := Config{}

	// Load env vars.
	if err := env.Parse(&conf); err != nil {
		return conf, err
	}

	return conf, nil
}
