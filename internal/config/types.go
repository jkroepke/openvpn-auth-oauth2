package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"golang.org/x/oauth2"
)

const (
	Plugin = iota
	ManagementClient
)

type Config struct {
	ConfigFile string  `json:"config"  yaml:"config"`
	Debug      Debug   `json:"debug"   yaml:"debug"`
	Log        Log     `json:"log"     yaml:"log"`
	HTTP       HTTP    `json:"http"    yaml:"http"`
	OpenVpn    OpenVpn `json:"openvpn" yaml:"openvpn"`
	OAuth2     OAuth2  `json:"oauth2"  yaml:"oauth2"`
}

type HTTP struct {
	Listen             string         `json:"listen"               yaml:"listen"`
	CertFile           string         `json:"cert"                 yaml:"cert"`
	KeyFile            string         `json:"key"                  yaml:"key"`
	TLS                bool           `json:"tls"                  yaml:"tls"`
	BaseURL            types.URL      `json:"baseurl"              yaml:"baseurl"`
	Secret             types.Secret   `json:"secret"               yaml:"secret"`
	Template           types.Template `json:"template"             yaml:"template"`
	Check              HTTPCheck      `json:"check"                yaml:"check"`
	EnableProxyHeaders bool           `json:"enable-proxy-headers" yaml:"enable-proxy-headers"`
	AssetPath          types.FS       `json:"assets-path"          yaml:"assets-path"`
}

type HTTPCheck struct {
	IPAddr bool `json:"ipaddr" yaml:"ipaddr"`
}

type Log struct {
	Format      string     `json:"format"        yaml:"format"`
	Level       slog.Level `json:"level"         yaml:"level"`
	VPNClientIP bool       `json:"vpn-client-ip" yaml:"vpn-client-ip"`
}

type OpenVpn struct {
	Addr               types.URL          `json:"addr"                 yaml:"addr"`
	Password           types.Secret       `json:"password"             yaml:"password"`
	Bypass             OpenVpnBypass      `json:"bypass"               yaml:"bypass"`
	CCD                OpenVPNCCD         `json:"ccd"                  yaml:"ccd"`
	AuthTokenUser      bool               `json:"auth-token-user"      yaml:"auth-token-user"`
	AuthPendingTimeout time.Duration      `json:"auth-pending-timeout" yaml:"auth-pending-timeout"`
	OverrideUsername   bool               `json:"override-username"    yaml:"override-username"`
	CommonName         OpenVPNCommonName  `json:"common-name"          yaml:"common-name"`
	Passthrough        OpenVPNPassthrough `json:"pass-through"         yaml:"pass-through"`
	CommandTimeout     time.Duration      `json:"command-timeout"      yaml:"command-timeout"`
}

type OpenVpnBypass struct {
	CommonNames types.StringSlice `json:"common-names" yaml:"common-names"`
}
type OpenVPNCCD struct {
	Enabled    bool     `json:"enabled"     yaml:"enabled"`
	TokenClaim string   `json:"token-claim" yaml:"token-claim"`
	Path       types.FS `json:"path"        yaml:"path"`
}

type OpenVPNCommonName struct {
	EnvironmentVariableName string                `json:"environment-variable-name" yaml:"environment-variable-name"`
	Mode                    OpenVPNCommonNameMode `json:"mode"                      yaml:"mode"`
}

type OAuth2 struct {
	AuthStyle       OAuth2AuthStyle   `json:"auth-style"       yaml:"auth-style"`
	AuthorizeParams string            `json:"authorize-params" yaml:"authorize-params"`
	Client          OAuth2Client      `json:"client"           yaml:"client"`
	Endpoints       OAuth2Endpoints   `json:"endpoint"         yaml:"endpoint"`
	Issuer          types.URL         `json:"issuer"           yaml:"issuer"`
	Nonce           bool              `json:"nonce"            yaml:"nonce"`
	PKCE            bool              `json:"pkce"             yaml:"pkce"`
	Provider        string            `json:"provider"         yaml:"provider"`
	Refresh         OAuth2Refresh     `json:"refresh"          yaml:"refresh"`
	Scopes          types.StringSlice `json:"scopes"           yaml:"scopes"`
	Validate        OAuth2Validate    `json:"validate"         yaml:"validate"`
}

type OAuth2Client struct {
	ID           string       `json:"id"             yaml:"id"`
	Secret       types.Secret `json:"secret"         yaml:"secret"`
	PrivateKey   types.Secret `json:"private-key"    yaml:"private-key"`
	PrivateKeyID string       `json:"private-key-id" yaml:"private-key-id"`
}

type OAuth2Endpoints struct {
	Discovery types.URL `json:"discovery" yaml:"discovery"`
	Auth      types.URL `json:"auth"      yaml:"auth"`
	Token     types.URL `json:"token"     yaml:"token"`
}

type OAuth2Validate struct {
	Acr                     types.StringSlice `json:"acr"                        yaml:"acr"`
	Groups                  types.StringSlice `json:"groups"                     yaml:"groups"`
	Roles                   types.StringSlice `json:"roles"                      yaml:"roles"`
	IPAddr                  bool              `json:"ipaddr"                     yaml:"ipaddr"`
	Issuer                  bool              `json:"issuer"                     yaml:"issuer"`
	CommonName              string            `json:"common-name"                yaml:"common-name"`
	CommonNameCaseSensitive bool              `json:"common-name-case-sensitive" yaml:"common-name-case-sensitive"`
}

type OAuth2Refresh struct {
	Enabled      bool          `json:"enabled"        yaml:"enabled"`
	Expires      time.Duration `json:"expires"        yaml:"expires"`
	Secret       types.Secret  `json:"secret"         yaml:"secret"`
	UseSessionID bool          `json:"use-session-id" yaml:"use-session-id"`
	ValidateUser bool          `json:"validate-user"  yaml:"validate-user"`
}

type OpenVPNPassthrough struct {
	Enabled     bool         `json:"enabled"      yaml:"enabled"`
	Address     types.URL    `json:"address"      yaml:"address"`
	Password    types.Secret `json:"password"     yaml:"password"`
	SocketMode  uint         `json:"socket-mode"  yaml:"socket-mode"`
	SocketGroup string       `json:"socket-group" yaml:"socket-group"`
}

type Debug struct {
	Pprof  bool   `json:"pprof"  yaml:"pprof"`
	Listen string `json:"listen" yaml:"listen"`
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

//goland:noinspection GoMixedReceiverTypes
func (c Config) String() string {
	jsonString, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}

	return string(jsonString)
}

func (h HTTP) MarshalJSON() ([]byte, error) {
	type Alias HTTP

	//nolint:wrapcheck
	return json.Marshal(&struct {
		Alias
	}{
		Alias: (Alias)(h),
	})
}
