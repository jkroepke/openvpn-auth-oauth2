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

//goland:noinspection GoUnusedConst
const (
	Plugin = iota
	ManagementClient
)

type Config struct {
	ConfigFile string  `json:"config"  yaml:"config"`
	HTTP       HTTP    `json:"http"    yaml:"http"`
	Debug      Debug   `json:"debug"   yaml:"debug"`
	Log        Log     `json:"log"     yaml:"log"`
	OpenVPN    OpenVPN `json:"openvpn" yaml:"openvpn"`
	OAuth2     OAuth2  `json:"oauth2"  yaml:"oauth2"`
}

type HTTP struct {
	BaseURL            types.URL      `json:"baseurl"              yaml:"baseurl"`
	AssetPath          types.FS       `json:"assets-path"          yaml:"assets-path"`
	Template           types.Template `json:"template"             yaml:"template"`
	Listen             string         `json:"listen"               yaml:"listen"`
	CertFile           string         `json:"cert"                 yaml:"cert"`
	KeyFile            string         `json:"key"                  yaml:"key"`
	Secret             types.Secret   `json:"secret"               yaml:"secret"`
	TLS                bool           `json:"tls"                  yaml:"tls"`
	Check              HTTPCheck      `json:"check"                yaml:"check"`
	EnableProxyHeaders bool           `json:"enable-proxy-headers" yaml:"enable-proxy-headers"`
}

type HTTPCheck struct {
	IPAddr bool `json:"ipaddr" yaml:"ipaddr"`
}

type Log struct {
	Format      string     `json:"format"        yaml:"format"`
	Level       slog.Level `json:"level"         yaml:"level"`
	VPNClientIP bool       `json:"vpn-client-ip" yaml:"vpn-client-ip"`
}

type OpenVPN struct {
	Addr               types.URL          `json:"addr"                 yaml:"addr"`
	Password           types.Secret       `json:"password"             yaml:"password"`
	ClientConfig       OpenVPNConfig      `json:"client-config"        yaml:"client-config"`
	Bypass             OpenVPNBypass      `json:"bypass"               yaml:"bypass"`
	CommonName         OpenVPNCommonName  `json:"common-name"          yaml:"common-name"`
	Passthrough        OpenVPNPassthrough `json:"pass-through"         yaml:"pass-through"`
	AuthPendingTimeout time.Duration      `json:"auth-pending-timeout" yaml:"auth-pending-timeout"`
	CommandTimeout     time.Duration      `json:"command-timeout"      yaml:"command-timeout"`
	AuthTokenUser      bool               `json:"auth-token-user"      yaml:"auth-token-user"`
	OverrideUsername   bool               `json:"override-username"    yaml:"override-username"`
	ReAuthentication   bool               `json:"reauthentication"     yaml:"reauthentication"`
}

type OpenVPNBypass struct {
	CommonNames types.RegexpSlice `json:"common-names" yaml:"common-names"`
}
type OpenVPNConfig struct {
	Path       types.FS `json:"path"        yaml:"path"`
	TokenClaim string   `json:"token-claim" yaml:"token-claim"`
	Enabled    bool     `json:"enabled"     yaml:"enabled"`
}

type OpenVPNCommonName struct {
	EnvironmentVariableName string                `json:"environment-variable-name" yaml:"environment-variable-name"`
	Mode                    OpenVPNCommonNameMode `json:"mode"                      yaml:"mode"`
}

type OAuth2 struct {
	Endpoints       OAuth2Endpoints    `json:"endpoint"         yaml:"endpoint"`
	Issuer          types.URL          `json:"issuer"           yaml:"issuer"`
	Client          OAuth2Client       `json:"client"           yaml:"client"`
	GroupsClaim     string             `json:"groups-claim"     yaml:"groups-claim"`
	AuthorizeParams string             `json:"authorize-params" yaml:"authorize-params"`
	Provider        string             `json:"provider"         yaml:"provider"`
	Scopes          types.StringSlice  `json:"scopes"           yaml:"scopes"`
	Validate        OAuth2Validate     `json:"validate"         yaml:"validate"`
	Refresh         OAuth2Refresh      `json:"refresh"          yaml:"refresh"`
	AuthStyle       OAuth2AuthStyle    `json:"auth-style"       yaml:"auth-style"`
	RefreshNonce    OAuth2RefreshNonce `json:"refresh-nonce"    yaml:"refresh-nonce"`
	Nonce           bool               `json:"nonce"            yaml:"nonce"`
	PKCE            bool               `json:"pkce"             yaml:"pkce"`
	UserInfo        bool               `json:"user-info"        yaml:"user-info"`
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
	CommonName              string            `json:"common-name"                yaml:"common-name"`
	Acr                     types.StringSlice `json:"acr"                        yaml:"acr"`
	Groups                  types.StringSlice `json:"groups"                     yaml:"groups"`
	Roles                   types.StringSlice `json:"roles"                      yaml:"roles"`
	IPAddr                  bool              `json:"ipaddr"                     yaml:"ipaddr"`
	Issuer                  bool              `json:"issuer"                     yaml:"issuer"`
	CommonNameCaseSensitive bool              `json:"common-name-case-sensitive" yaml:"common-name-case-sensitive"`
}

type OAuth2Refresh struct {
	Secret       types.Secret  `json:"secret"         yaml:"secret"`
	Expires      time.Duration `json:"expires"        yaml:"expires"`
	Enabled      bool          `json:"enabled"        yaml:"enabled"`
	UseSessionID bool          `json:"use-session-id" yaml:"use-session-id"`
	ValidateUser bool          `json:"validate-user"  yaml:"validate-user"`
}

type OpenVPNPassthrough struct {
	Address     types.URL    `json:"address"      yaml:"address"`
	Password    types.Secret `json:"password"     yaml:"password"`
	SocketGroup string       `json:"socket-group" yaml:"socket-group"`
	SocketMode  uint         `json:"socket-mode"  yaml:"socket-mode"`
	Enabled     bool         `json:"enabled"      yaml:"enabled"`
}

type Debug struct {
	Listen string `json:"listen" yaml:"listen"`
	Pprof  bool   `json:"pprof"  yaml:"pprof"`
}

type OpenVPNCommonNameMode int

const (
	CommonNameModePlain OpenVPNCommonNameMode = iota
	CommonNameModeOmit
	CommonNameModeOmitValue = "-"
)

// String returns the string representation of the common name mode.
//
//goland:noinspection GoMixedReceiverTypes
func (s OpenVPNCommonNameMode) String() string {
	text, err := s.MarshalText()
	if err != nil {
		panic(err)
	}

	return string(text)
}

// MarshalText implements the [encoding.TextMarshaler] interface.
//
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

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
//
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

// String returns the string representation of the auth style.
//
//goland:noinspection GoMixedReceiverTypes
func (s OAuth2AuthStyle) String() string {
	text, err := s.MarshalText()
	if err != nil {
		panic(err)
	}

	return string(text)
}

// AuthStyle converts the wrapper type to [oauth2.AuthStyle].
//
//goland:noinspection GoMixedReceiverTypes
func (s OAuth2AuthStyle) AuthStyle() oauth2.AuthStyle {
	return oauth2.AuthStyle(s)
}

// MarshalText implements the [encoding.TextMarshaler] interface.
//
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
		return nil, fmt.Errorf("unknown auth-style: %d", s)
	}
}

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (s *OAuth2AuthStyle) UnmarshalText(text []byte) error {
	switch strings.ToLower(string(text)) {
	case "authstyleautodetect":
		*s = OAuth2AuthStyle(oauth2.AuthStyleAutoDetect)
	case "authstyleinparams":
		*s = OAuth2AuthStyle(oauth2.AuthStyleInParams)
	case "authstyleinheader":
		*s = OAuth2AuthStyle(oauth2.AuthStyleInHeader)
	default:
		return fmt.Errorf("unknown auth-style: %s", text)
	}

	return nil
}

type OAuth2RefreshNonce int

const (
	OAuth2RefreshNonceAuto OAuth2RefreshNonce = iota
	OAuth2RefreshNonceEmpty
	OAuth2RefreshNonceEqual
)

// String returns the string representation of the refresh nonce mode.
//
//goland:noinspection GoMixedReceiverTypes
func (s OAuth2RefreshNonce) String() string {
	text, err := s.MarshalText()
	if err != nil {
		panic(err)
	}

	return string(text)
}

// MarshalText implements the [encoding.TextMarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (s OAuth2RefreshNonce) MarshalText() ([]byte, error) {
	switch s {
	case OAuth2RefreshNonceAuto:
		return []byte("auto"), nil
	case OAuth2RefreshNonceEmpty:
		return []byte("empty"), nil
	case OAuth2RefreshNonceEqual:
		return []byte("equal"), nil
	default:
		return nil, fmt.Errorf("unknown refresh-nonce %d", s)
	}
}

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (s *OAuth2RefreshNonce) UnmarshalText(text []byte) error {
	config := strings.ToLower(string(text))
	switch config {
	case "auto":
		*s = OAuth2RefreshNonceAuto
	case "empty":
		*s = OAuth2RefreshNonceEmpty
	case "equal":
		*s = OAuth2RefreshNonceEqual
	default:
		return fmt.Errorf("invalid value %s", config)
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
