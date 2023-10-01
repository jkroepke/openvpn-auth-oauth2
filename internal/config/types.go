package config

import (
	"html/template"
	"net/url"
)

type Config struct {
	ConfigFile string  `koanf:"config"`
	Log        Log     `koanf:"log"`
	Http       Http    `koanf:"http"`
	OpenVpn    OpenVpn `koanf:"openvpn"`
	Oauth2     OAuth2  `koanf:"oauth2"`
}

type Http struct {
	Listen             string             `koanf:"listen"`
	CertFile           string             `koanf:"cert"`
	KeyFile            string             `koanf:"key"`
	Tls                bool               `koanf:"tls"`
	BaseUrl            *url.URL           `koanf:"baseurl"`
	Secret             string             `koanf:"secret"`
	CallbackTemplate   *template.Template `koanf:"callback-template-path"`
	Check              HttpCheck          `koanf:"check"`
	EnableProxyHeaders bool               `koanf:"enable-proxy-headers"`
}

type HttpCheck struct {
	IpAddr bool `koanf:"ipaddr"`
}

type Log struct {
	Format string `koanf:"format"`
	Level  string `koanf:"level"`
}

type OpenVpn struct {
	Addr          *url.URL      `koanf:"addr"`
	Password      string        `koanf:"password"`
	Bypass        OpenVpnBypass `koanf:"bypass"`
	AuthTokenUser bool          `koanf:"auth-token-user"`
}

type OpenVpnBypass struct {
	CommonNames []string `koanf:"cn"`
}

type OAuth2 struct {
	Issuer          *url.URL        `koanf:"issuer"`
	Provider        string          `koanf:"provider"`
	AuthorizeParams string          `koanf:"authorize-params"`
	Endpoints       OAuth2Endpoints `koanf:"endpoint"`
	Client          OAuth2Client    `koanf:"client"`
	Scopes          []string        `koanf:"scopes"`
	Pkce            bool            `koanf:"pkce"`
	Validate        OAuth2Validate  `koanf:"validate"`
}

type OAuth2Client struct {
	Id     string `koanf:"id"`
	Secret string `koanf:"secret"`
}

type OAuth2Endpoints struct {
	Discovery *url.URL `koanf:"discovery"`
	Auth      *url.URL `koanf:"auth"`
	Token     *url.URL `koanf:"token"`
}

type OAuth2Validate struct {
	Groups     []string `koanf:"groups"`
	Roles      []string `koanf:"roles"`
	IpAddr     bool     `koanf:"ipaddr"`
	Issuer     bool     `koanf:"issuer"`
	CommonName string   `koanf:"common_name"`
}
