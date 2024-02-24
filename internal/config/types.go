package config

import (
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"text/template"
	"time"

	"golang.org/x/oauth2"
)

type Config struct {
	ConfigFile string  `koanf:"config"`
	Debug      Debug   `koanf:"debug"`
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
	Addr               *url.URL           `koanf:"addr"`
	Password           Secret             `koanf:"password"`
	Bypass             OpenVpnBypass      `koanf:"bypass"`
	AuthTokenUser      bool               `koanf:"auth-token-user"`
	AuthPendingTimeout time.Duration      `koanf:"auth-pending-timeout"`
	CommonName         OpenVPNCommonName  `koanf:"common-name"`
	Passthrough        OpenVPNPassthrough `koanf:"pass-through"`
}

type OpenVpnBypass struct {
	CommonNames StringSlice `koanf:"common-names"`
}

type OpenVPNCommonName struct {
	EnvironmentVariableName string                `koanf:"environment-variable-name"`
	Mode                    OpenVPNCommonNameMode `koanf:"mode"`
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
	AuthStyle       OAuth2AuthStyle `koanf:"auth-style"`
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
	Acr                     StringSlice `koanf:"acr"`
	Groups                  StringSlice `koanf:"groups"`
	Roles                   StringSlice `koanf:"roles"`
	IPAddr                  bool        `koanf:"ipaddr"`
	Issuer                  bool        `koanf:"issuer"`
	CommonName              string      `koanf:"common-name"`
	CommonNameCaseSensitive bool        `koanf:"common-name-case-sensitive"`
}

type OAuth2Refresh struct {
	Enabled      bool          `koanf:"enabled"`
	Expires      time.Duration `koanf:"expires"`
	Secret       Secret        `koanf:"secret"`
	UseSessionID bool          `koanf:"use-session-id"`
	ValidateUser bool          `koanf:"validate-user"`
}

type OpenVPNPassthrough struct {
	Enabled     bool     `koanf:"enabled"`
	Address     *url.URL `koanf:"address"`
	Password    Secret   `koanf:"password"`
	SocketMode  uint     `koanf:"socket-mode"`
	SocketGroup string   `koanf:"socket-group"`
}

type Debug struct {
	Pprof  bool   `koanf:"pprof"`
	Listen string `koanf:"listen"`
}

type OpenVPNCommonNameMode int

const (
	CommonNameModePlain OpenVPNCommonNameMode = iota
	CommonNameModeOmit
	CommonNameModeOmitValue = "-"
)

//goland:noinspection GoMixedReceiverTypes
func (s OpenVPNCommonNameMode) String() string {
	text, err := s.MarshalText()
	if err != nil {
		panic(err)
	}

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

type OAuth2AuthStyle oauth2.AuthStyle

//goland:noinspection GoMixedReceiverTypes
func (s OAuth2AuthStyle) String() string {
	text, err := s.MarshalText()
	if err != nil {
		panic(err)
	}

	return string(text)
}

//goland:noinspection GoMixedReceiverTypes
func (s OAuth2AuthStyle) AuthStyle() oauth2.AuthStyle {
	return oauth2.AuthStyle(s)
}

//goland:noinspection GoMixedReceiverTypes
func (s OAuth2AuthStyle) MarshalText() ([]byte, error) {
	switch s {
	case OAuth2AuthStyle(oauth2.AuthStyleAutoDetect):
		return []byte("AuthStyleAutoDetect"), nil
	case OAuth2AuthStyle(oauth2.AuthStyleInParams):
		return []byte("AuthStyleInParams"), nil
	case OAuth2AuthStyle(oauth2.AuthStyleInHeader):
		return []byte("AuthStyleInHeader"), nil
	default:
		return nil, fmt.Errorf("unknown auth-style %d", s)
	}
}

//goland:noinspection GoMixedReceiverTypes
func (s *OAuth2AuthStyle) UnmarshalText(text []byte) error {
	config := strings.ToLower(string(text))
	switch config {
	case strings.ToLower("AuthStyleAutoDetect"):
		*s = OAuth2AuthStyle(oauth2.AuthStyleAutoDetect)
	case strings.ToLower("AuthStyleInParams"):
		*s = OAuth2AuthStyle(oauth2.AuthStyleInParams)
	case strings.ToLower("AuthStyleInHeader"):
		*s = OAuth2AuthStyle(oauth2.AuthStyleInHeader)
	default:
		return fmt.Errorf("unknown auth-style %d", s)
	}

	return nil
}
