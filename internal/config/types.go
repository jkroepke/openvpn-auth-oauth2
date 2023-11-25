package config

import (
	"log/slog"
	"net/url"
	"text/template"
	"time"
)

type Config struct {
	ConfigFile string  `koanf:"config"`
	Log        Log     `koanf:"log"`
	HTTP       HTTP    `koanf:"http"`
	OpenVpn    OpenVpn `koanf:"openvpn"`
	OAuth2     OAuth2  `koanf:"oauth2"`
}

type HTTP struct {
	Listen             string             `koanf:"listen"`
	CertFile           string             `koanf:"cert"`
	KeyFile            string             `koanf:"key"`
	TLS                bool               `koanf:"tls"`
	BaseURL            *url.URL           `koanf:"baseurl"`
	Secret             Secret             `koanf:"secret"`
	CallbackTemplate   *template.Template `koanf:"template"`
	Check              HTTPCheck          `koanf:"check"`
	EnableProxyHeaders bool               `koanf:"enable-proxy-headers"`
}

type HTTPCheck struct {
	IPAddr bool `koanf:"ipaddr"`
}

type Log struct {
	Format string     `koanf:"format"`
	Level  slog.Level `koanf:"level"`
}

type OpenVpn struct {
	Addr               *url.URL      `koanf:"addr"`
	Password           Secret        `koanf:"password"`
	Bypass             OpenVpnBypass `koanf:"bypass"`
	AuthTokenUser      bool          `koanf:"auth-token-user"`
	AuthPendingTimeout time.Duration `koanf:"auth-pending-timeout"`
}

type OpenVpnBypass struct {
	CommonNames StringSlice `koanf:"cn"`
}

type OAuth2 struct {
	Issuer          *url.URL        `koanf:"issuer"`
	Provider        string          `koanf:"provider"`
	AuthorizeParams string          `koanf:"authorize-params"`
	Endpoints       OAuth2Endpoints `koanf:"endpoint"`
	Client          OAuth2Client    `koanf:"client"`
	Scopes          StringSlice     `koanf:"scopes"`
	Pkce            bool            `koanf:"pkce"`
	Validate        OAuth2Validate  `koanf:"validate"`
}

type OAuth2Client struct {
	ID     string `koanf:"id"`
	Secret Secret `koanf:"secret"`
}

type OAuth2Endpoints struct {
	Discovery *url.URL `koanf:"discovery"`
	Auth      *url.URL `koanf:"auth"`
	Token     *url.URL `koanf:"token"`
}

type OAuth2Validate struct {
	Groups     StringSlice `koanf:"groups"`
	Roles      StringSlice `koanf:"roles"`
	IPAddr     bool        `koanf:"ipaddr"`
	Issuer     bool        `koanf:"issuer"`
	CommonName string      `koanf:"common_name"`
}
