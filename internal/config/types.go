package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"text/template"
	"time"

	"golang.org/x/oauth2"
)

type Config struct {
	ConfigFile string  `json:"config"  koanf:"config"`
	Debug      Debug   `json:"debug"   koanf:"debug"`
	Log        Log     `json:"log"     koanf:"log"`
	HTTP       HTTP    `json:"http"    koanf:"http"`
	OpenVpn    OpenVpn `json:"openvpn" koanf:"openvpn"`
	OAuth2     OAuth2  `json:"oauth2"  koanf:"oauth2"`
}

type HTTP struct {
	Listen             string             `json:"listen"               koanf:"listen"`
	CertFile           string             `json:"cert"                 koanf:"cert"`
	KeyFile            string             `json:"key"                  koanf:"key"`
	TLS                bool               `json:"tls"                  koanf:"tls"`
	BaseURL            *URL               `json:"baseurl"              koanf:"baseurl"`
	Secret             Secret             `json:"secret"               koanf:"secret"`
	CallbackTemplate   *template.Template `json:"template,omitempty"   koanf:"template"`
	Check              HTTPCheck          `json:"check"                koanf:"check"`
	EnableProxyHeaders bool               `json:"enable-proxy-headers" koanf:"enable-proxy-headers"`
	AssetPath          string             `json:"assets-path"          koanf:"assets-path"`
}

type HTTPCheck struct {
	IPAddr bool `json:"ipaddr" koanf:"ipaddr"`
}

type Log struct {
	Format      string     `json:"format"        koanf:"format"`
	Level       slog.Level `json:"level"         koanf:"level"`
	VPNClientIP bool       `json:"vpn-client-ip" koanf:"vpn-client-ip"`
}

type OpenVpn struct {
	Addr               *URL               `json:"addr"                 koanf:"addr"`
	Password           Secret             `json:"password"             koanf:"password"`
	Bypass             OpenVpnBypass      `json:"bypass"               koanf:"bypass"`
	AuthTokenUser      bool               `json:"auth-token-user"      koanf:"auth-token-user"`
	AuthPendingTimeout time.Duration      `json:"auth-pending-timeout" koanf:"auth-pending-timeout"`
	OverrideUsername   bool               `json:"override-username"    koanf:"override-username"`
	CommonName         OpenVPNCommonName  `json:"common-name"          koanf:"common-name"`
	Passthrough        OpenVPNPassthrough `json:"pass-through"         koanf:"pass-through"`
	CommandTimeout     time.Duration      `json:"command-timeout"      koanf:"command-timeout"`
}

type OpenVpnBypass struct {
	CommonNames StringSlice `json:"common-names" koanf:"common-names"`
}

type OpenVPNCommonName struct {
	EnvironmentVariableName string                `json:"environment-variable-name" koanf:"environment-variable-name"`
	Mode                    OpenVPNCommonNameMode `json:"mode"                      koanf:"mode"`
}

type OAuth2 struct {
	AuthStyle       OAuth2AuthStyle `json:"auth-style"       koanf:"auth-style"`
	AuthorizeParams string          `json:"authorize-params" koanf:"authorize-params"`
	Client          OAuth2Client    `json:"client"           koanf:"client"`
	Endpoints       OAuth2Endpoints `json:"endpoint"         koanf:"endpoint"`
	Issuer          *URL            `json:"issuer"           koanf:"issuer"`
	Nonce           bool            `json:"nonce"            koanf:"nonce"`
	PKCE            bool            `json:"pkce"             koanf:"pkce"`
	Provider        string          `json:"provider"         koanf:"provider"`
	Refresh         OAuth2Refresh   `json:"refresh"          koanf:"refresh"`
	Scopes          StringSlice     `json:"scopes"           koanf:"scopes"`
	Validate        OAuth2Validate  `json:"validate"         koanf:"validate"`
}

type OAuth2Client struct {
	ID           string `json:"id"             koanf:"id"`
	Secret       Secret `json:"secret"         koanf:"secret"`
	PrivateKey   Secret `json:"private-key"    koanf:"private-key"`
	PrivateKeyID string `json:"private-key-id" koanf:"private-key-id"`
}

type OAuth2Endpoints struct {
	Discovery *URL `json:"discovery" koanf:"discovery"`
	Auth      *URL `json:"auth"      koanf:"auth"`
	Token     *URL `json:"token"     koanf:"token"`
}

type OAuth2Validate struct {
	Acr                     StringSlice `json:"acr"                        koanf:"acr"`
	Groups                  StringSlice `json:"groups"                     koanf:"groups"`
	Roles                   StringSlice `json:"roles"                      koanf:"roles"`
	IPAddr                  bool        `json:"ipaddr"                     koanf:"ipaddr"`
	Issuer                  bool        `json:"issuer"                     koanf:"issuer"`
	CommonName              string      `json:"common-name"                koanf:"common-name"`
	CommonNameCaseSensitive bool        `json:"common-name-case-sensitive" koanf:"common-name-case-sensitive"`
}

type OAuth2Refresh struct {
	Enabled      bool          `json:"enabled"        koanf:"enabled"`
	Expires      time.Duration `json:"expires"        koanf:"expires"`
	Secret       Secret        `json:"secret"         koanf:"secret"`
	UseSessionID bool          `json:"use-session-id" koanf:"use-session-id"`
	ValidateUser bool          `json:"validate-user"  koanf:"validate-user"`
}

type OpenVPNPassthrough struct {
	Enabled     bool   `json:"enabled"      koanf:"enabled"`
	Address     *URL   `json:"address"      koanf:"address"`
	Password    Secret `json:"password"     koanf:"password"`
	SocketMode  uint   `json:"socket-mode"  koanf:"socket-mode"`
	SocketGroup string `json:"socket-group" koanf:"socket-group"`
}

type Debug struct {
	Pprof  bool   `json:"pprof"  koanf:"pprof"`
	Listen string `json:"listen" koanf:"listen"`
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

func (h HTTP) MarshalJSON() ([]byte, error) {
	//nolint:revive
	h.CallbackTemplate = nil

	type Alias HTTP

	//nolint:wrapcheck
	return json.Marshal(&struct {
		Alias
	}{
		Alias: (Alias)(h),
	})
}
