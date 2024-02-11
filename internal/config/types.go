package config

import (
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"text/template"
	"time"
)

type Config struct {
	ConfigFile string   `koanf:"config"`
	Debug      Debug    `koanf:"debug"`
	Log        Log      `koanf:"log"`
	HTTP       HTTP     `koanf:"http"`
	OpenVpn    OpenVpn  `koanf:"openvpn"`
	OAuth2     OAuth2   `koanf:"oauth2"`
	Provider   Provider `koanf:"provider"`
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
	Addr               *url.URL          `koanf:"addr"`
	Password           Secret            `koanf:"password"`
	Bypass             OpenVpnBypass     `koanf:"bypass"`
	AuthTokenUser      bool              `koanf:"auth-token-user"`
	AuthPendingTimeout time.Duration     `koanf:"auth-pending-timeout"`
	CommonName         OpenVPNCommonName `koanf:"common-name"`
}

type OpenVpnBypass struct {
	CommonNames StringSlice `koanf:"common-names"`
}

type OpenVPNCommonName struct {
	Mode OpenVPNCommonNameMode `koanf:"mode"`
}

type OAuth2 struct {
	Issuer          *url.URL        `koanf:"issuer"`
	Provider        string          `koanf:"provider"`
	AuthorizeParams string          `koanf:"authorize-params"`
	Endpoints       OAuth2Endpoints `koanf:"endpoint"`
	Client          OAuth2Client    `koanf:"client"`
	Scopes          StringSlice     `koanf:"scopes"`
	Nonce           bool            `koanf:"nonce"`
	Pkce            bool            `koanf:"pkce"`
	Validate        OAuth2Validate  `koanf:"validate"`
	Refresh         OAuth2Refresh   `koanf:"refresh"`
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
	Acr        StringSlice `koanf:"acr"`
	Groups     StringSlice `koanf:"groups"`
	Roles      StringSlice `koanf:"roles"`
	IPAddr     bool        `koanf:"ipaddr"`
	Issuer     bool        `koanf:"issuer"`
	CommonName string      `koanf:"common-name"`
}

type OAuth2Refresh struct {
	Enabled bool          `koanf:"enabled"`
	Expires time.Duration `koanf:"expires"`
	Secret  Secret        `koanf:"secret"`
}

type Debug struct {
	Pprof  bool   `koanf:"pprof"`
	Listen string `koanf:"listen"`
}

type Provider struct {
	Google ProviderGoogle `koanf:"google"`
}

type ProviderGoogle struct {
	ServiceAccountConfig Secret `koanf:"service-account-config"`
	AdminEmail           string `koanf:"admin-email"`
	ImpersonateAccount   string `koanf:"impersonate-account"`
}

type OpenVPNCommonNameMode int

const (
	CommonNameModePlain OpenVPNCommonNameMode = iota
	CommonNameModeOmit
	CommonNameModeOmitValue = "-"
)

//goland:noinspection GoMixedReceiverTypes
func (s OpenVPNCommonNameMode) String() string {
	text, _ := s.MarshalText()

	return string(text)
}

//goland:noinspection GoMixedReceiverTypes
func (s OpenVPNCommonNameMode) MarshalText() ([]byte, error) {
	switch s {
	case CommonNameModePlain:
		return []byte("plain"), nil
	case CommonNameModeOmit:
		return []byte("omit"), nil
	default:
		return nil, fmt.Errorf("unknown identitfer %d", s)
	}
}

//goland:noinspection GoMixedReceiverTypes
func (s *OpenVPNCommonNameMode) UnmarshalText(text []byte) error {
	config := strings.ToLower(string(text))
	switch config {
	case "plain":
		*s = CommonNameModePlain
	case "omit":
		*s = CommonNameModeOmit
	default:
		return fmt.Errorf("invalid value %s", config)
	}

	return nil
}
