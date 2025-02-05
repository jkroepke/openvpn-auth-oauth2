package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"text/template"
	"time"

	"golang.org/x/oauth2"
)

type Config struct {
	ConfigFile string  `koanf:"config" json:"config"`
	Debug      Debug   `koanf:"debug" json:"debug"`
	Log        Log     `koanf:"log" json:"log"`
	HTTP       HTTP    `koanf:"http" json:"http"`
	OpenVpn    OpenVpn `koanf:"openvpn" json:"openvpn"`
	OAuth2     OAuth2  `koanf:"oauth2" json:"oauth2"`
}

type HTTP struct {
	Listen             string             `koanf:"listen" json:"listen"`
	CertFile           string             `koanf:"cert" json:"cert"`
	KeyFile            string             `koanf:"key" json:"key"`
	TLS                bool               `koanf:"tls" json:"tls"`
	BaseURL            *url.URL           `koanf:"baseurl" json:"baseurl"`
	Secret             Secret             `koanf:"secret" json:"secret"`
	CallbackTemplate   *template.Template `koanf:"template" json:"template,omitempty"`
	Check              HTTPCheck          `koanf:"check" json:"check"`
	EnableProxyHeaders bool               `koanf:"enable-proxy-headers" json:"enable-proxy-headers"`
	AssetPath          string             `koanf:"assets-path" json:"assets-path"`
}

type HTTPCheck struct {
	IPAddr bool `koanf:"ipaddr" json:"ipaddr"`
}

type Log struct {
	Format      string     `koanf:"format" json:"format"`
	Level       slog.Level `koanf:"level" json:"level"`
	VPNClientIP bool       `koanf:"vpn-client-ip" json:"vpn-client-ip"`
}

type OpenVpn struct {
	Addr               *url.URL           `koanf:"addr" json:"addr"`
	Password           Secret             `koanf:"password" json:"password"`
	Bypass             OpenVpnBypass      `koanf:"bypass" json:"bypass"`
	AuthTokenUser      bool               `koanf:"auth-token-user" json:"auth-token-user"`
	AuthPendingTimeout time.Duration      `koanf:"auth-pending-timeout" json:"auth-pending-timeout"`
	CommonName         OpenVPNCommonName  `koanf:"common-name" json:"common-name"`
	Passthrough        OpenVPNPassthrough `koanf:"pass-through" json:"pass-through"`
}

type OpenVpnBypass struct {
	CommonNames StringSlice `koanf:"common-names" json:"common-names"`
}

type OpenVPNCommonName struct {
	EnvironmentVariableName string                `koanf:"environment-variable-name" json:"environment-variable-name"`
	Mode                    OpenVPNCommonNameMode `koanf:"mode" json:"mode"`
}

type OAuth2 struct {
	AuthStyle       OAuth2AuthStyle `koanf:"auth-style" json:"auth-style"`
	AuthorizeParams string          `koanf:"authorize-params" json:"authorize-params"`
	Client          OAuth2Client    `koanf:"client" json:"client"`
	Endpoints       OAuth2Endpoints `koanf:"endpoint" json:"endpoint"`
	Issuer          *url.URL        `koanf:"issuer" json:"issuer"`
	Nonce           bool            `koanf:"nonce" json:"nonce"`
	PKCE            bool            `koanf:"pkce" json:"pkce"`
	Provider        string          `koanf:"provider" json:"provider"`
	Refresh         OAuth2Refresh   `koanf:"refresh" json:"refresh"`
	Scopes          StringSlice     `koanf:"scopes" json:"scopes"`
	Validate        OAuth2Validate  `koanf:"validate" json:"validate"`
}

type OAuth2Client struct {
	ID     string `koanf:"id" json:"id"`
	Secret Secret `koanf:"secret" json:"secret"`
}

type OAuth2Endpoints struct {
	Discovery *url.URL `koanf:"discovery" json:"discovery"`
	Auth      *url.URL `koanf:"auth" json:"auth"`
	Token     *url.URL `koanf:"token" json:"token"`
}

type OAuth2Validate struct {
	Acr                     StringSlice `koanf:"acr" json:"acr"`
	Groups                  StringSlice `koanf:"groups" json:"groups"`
	Roles                   StringSlice `koanf:"roles" json:"roles"`
	IPAddr                  bool        `koanf:"ipaddr" json:"ipaddr"`
	Issuer                  bool        `koanf:"issuer" json:"issuer"`
	CommonName              string      `koanf:"common-name" json:"common-name"`
	CommonNameCaseSensitive bool        `koanf:"common-name-case-sensitive" json:"common-name-case-sensitive"`
}

type OAuth2Refresh struct {
	Enabled      bool          `koanf:"enabled" json:"enabled"`
	Expires      time.Duration `koanf:"expires" json:"expires"`
	Secret       Secret        `koanf:"secret" json:"secret"`
	UseSessionID bool          `koanf:"use-session-id" json:"use-session-id"`
	ValidateUser bool          `koanf:"validate-user" json:"validate-user"`
}

type OpenVPNPassthrough struct {
	Enabled     bool     `koanf:"enabled" json:"enabled"`
	Address     *url.URL `koanf:"address" json:"address"`
	Password    Secret   `koanf:"password" json:"password"`
	SocketMode  uint     `koanf:"socket-mode" json:"socket-mode"`
	SocketGroup string   `koanf:"socket-group" json:"socket-group"`
}

type Debug struct {
	Pprof  bool   `koanf:"pprof" json:"pprof"`
	Listen string `koanf:"listen" json:"listen"`
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

func (c Config) String() string {
	jsonString, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}

	return string(jsonString)
}
