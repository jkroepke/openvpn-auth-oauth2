package config

import (
	"github.com/caarlos0/env/v8"
	commonConfig "github.com/jkroepke/openvpn-auth-oauth2/internal/config"
)

type Config struct {
	commonConfig.Config

	AuthTimeout int              `env:"OPENVPN_AUTH_OAUTH2_AUTH_TIMEOUT" envDefault:"300"`
	Management  ManagementConfig `envPrefix:"OPENVPN_AUTH_OAUTH2_MANAGEMENT"`
}

type ManagementConfig struct {
	Host     string `env:"HOST" envDefault:""`
	Port     uint16 `env:"PORT" envDefault:"0"`
	Socket   string `env:"SOCKET" envDefault:""`
	Password string `env:"PASSWORD" envDefault:""`
}

func LoadConfig() (Config, error) {
	conf := Config{}

	// Load env vars.
	if err := env.Parse(&conf); err != nil {
		return conf, err
	}

	return conf, nil
}
