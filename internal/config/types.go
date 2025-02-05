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
	ConfigFile string  `json:"config"`
	Debug      Debug   `json:"debug"`
	Log        Log     `json:"log"`
	HTTP       HTTP    `json:"http"`
	OpenVpn    OpenVpn `json:"openvpn"`
	OAuth2     OAuth2  `json:"oauth2"`
}

type HTTP struct {
	Listen             string             `json:"listen"`
	CertFile           string             `json:"cert"`
	KeyFile            string             `json:"key"`
	TLS                bool               `json:"tls"`
	BaseURL            *url.URL           `json:"baseurl"`
	Secret             Secret             `json:"secret"`
	CallbackTemplate   *template.Template `json:"template"`
	Check              HTTPCheck          `json:"check"`
	EnableProxyHeaders bool               `json:"enable-proxy-headers"`
	AssetPath          string             `json:"assets-path"`
}

type HTTPCheck struct {
	IPAddr bool `json:"ipaddr"`
}

type Log struct {
	Format      string     `json:"format"`
	Level       slog.Level `json:"level"`
	VPNClientIP bool       `json:"vpn-client-ip"`
}

type OpenVpn struct {
	Addr               *url.URL           `json:"addr"`
	Password           Secret             `json:"password"`
	Bypass             OpenVpnBypass      `json:"bypass"`
	AuthTokenUser      bool               `json:"auth-token-user"`
	AuthPendingTimeout time.Duration      `json:"auth-pending-timeout"`
	CommonName         OpenVPNCommonName  `json:"common-name"`
	Passthrough        OpenVPNPassthrough `json:"pass-through"`
}

type OpenVpnBypass struct {
	CommonNames StringSlice `json:"common-names"`
}

type OpenVPNCommonName struct {
	EnvironmentVariableName string                `json:"environment-variable-name"`
	Mode                    OpenVPNCommonNameMode `json:"mode"`
}

type OAuth2 struct {
	AuthStyle       OAuth2AuthStyle `json:"auth-style"`
	AuthorizeParams string          `json:"authorize-params"`
	Client          OAuth2Client    `json:"client"`
	Endpoints       OAuth2Endpoints `json:"endpoint"`
	Issuer          *url.URL        `json:"issuer"`
	Nonce           bool            `json:"nonce"`
	PKCE            bool            `json:"pkce"`
	Provider        string          `json:"provider"`
	Refresh         OAuth2Refresh   `json:"refresh"`
	Scopes          StringSlice     `json:"scopes"`
	Validate        OAuth2Validate  `json:"validate"`
}

type OAuth2Client struct {
	ID     string `json:"id"`
	Secret Secret `json:"secret"`
}

type OAuth2Endpoints struct {
	Discovery *url.URL `json:"discovery"`
	Auth      *url.URL `json:"auth"`
	Token     *url.URL `json:"token"`
}

type OAuth2Validate struct {
	Acr                     StringSlice `json:"acr"`
	Groups                  StringSlice `json:"groups"`
	Roles                   StringSlice `json:"roles"`
	IPAddr                  bool        `json:"ipaddr"`
	Issuer                  bool        `json:"issuer"`
	CommonName              string      `json:"common-name"`
	CommonNameCaseSensitive bool        `json:"common-name-case-sensitive"`
}

type OAuth2Refresh struct {
	Enabled      bool          `json:"enabled"`
	Expires      time.Duration `json:"expires"`
	Secret       Secret        `json:"secret"`
	UseSessionID bool          `json:"use-session-id"`
	ValidateUser bool          `json:"validate-user"`
}

type OpenVPNPassthrough struct {
	Enabled     bool     `json:"enabled"`
	Address     *url.URL `json:"address"`
	Password    Secret   `json:"password"`
	SocketMode  uint     `json:"socket-mode"`
	SocketGroup string   `json:"socket-group"`
}

type Debug struct {
	Pprof  bool   `json:"pprof"`
	Listen string `json:"listen"`
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
