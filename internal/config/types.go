package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
)

// Type aliases for backward compatibility.
// These types are now defined in the types/ subdirectory.
type (
	OpenVPNCommonNameMode = types.OpenVPNCommonNameMode
	OAuth2AuthStyle       = types.OAuth2AuthStyle
	OAuth2RefreshNonce    = types.OAuth2RefreshNonce
)

// Constants for backward compatibility.
const (
	CommonNameModePlain     = types.CommonNameModePlain
	CommonNameModeOmit      = types.CommonNameModeOmit
	CommonNameModeOmitValue = types.CommonNameModeOmitValue

	OAuth2RefreshNonceAuto  = types.OAuth2RefreshNonceAuto
	OAuth2RefreshNonceEmpty = types.OAuth2RefreshNonceEmpty
	OAuth2RefreshNonceEqual = types.OAuth2RefreshNonceEqual
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
	OAuth2     OAuth2  `json:"oauth2"  yaml:"oauth2"`
	OpenVPN    OpenVPN `json:"openvpn" yaml:"openvpn"`
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
	ShortURL           bool           `json:"short-url"            yaml:"short-url"`
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
	Bypass             OpenVPNBypass      `json:"bypass"               yaml:"bypass"`
	CommonName         OpenVPNCommonName  `json:"common-name"          yaml:"common-name"`
	Passthrough        OpenVPNPassthrough `json:"pass-through"         yaml:"pass-through"`
	ClientConfig       OpenVPNConfig      `json:"client-config"        yaml:"client-config"`
	AuthPendingTimeout time.Duration      `json:"auth-pending-timeout" yaml:"auth-pending-timeout"`
	CommandTimeout     time.Duration      `json:"command-timeout"      yaml:"command-timeout"`
	OverrideUsername   bool               `json:"override-username"    yaml:"override-username"`
	ReAuthentication   bool               `json:"reauthentication"     yaml:"reauthentication"`
	AuthTokenUser      bool               `json:"auth-token-user"      yaml:"auth-token-user"`
}

type OpenVPNBypass struct {
	CommonNames types.RegexpSlice `json:"common-names" yaml:"common-names"`
}
type OpenVPNConfig struct {
	Path         types.FS                     `json:"path"          yaml:"path"`
	TokenClaim   string                       `json:"token-claim"   yaml:"token-claim"`
	UserSelector OpenVPNConfigProfileSelector `json:"user-selector" yaml:"user-selector"`
	Enabled      bool                         `json:"enabled"       yaml:"enabled"`
}

type OpenVPNConfigProfileSelector struct {
	StaticValues types.StringSlice `json:"static-values" yaml:"static-values"`
	Enabled      bool              `json:"enabled"       yaml:"enabled"`
}

type OpenVPNCommonName struct {
	EnvironmentVariableName string                `json:"environment-variable-name" yaml:"environment-variable-name"`
	Mode                    OpenVPNCommonNameMode `json:"mode"                      yaml:"mode"`
}

type OAuth2 struct {
	Endpoints            OAuth2Endpoints    `json:"endpoint"               yaml:"endpoint"`
	Issuer               types.URL          `json:"issuer"                 yaml:"issuer"`
	Client               OAuth2Client       `json:"client"                 yaml:"client"`
	OpenVPNUsernameClaim string             `json:"openvpn-username-claim" yaml:"openvpn-username-claim"`
	GroupsClaim          string             `json:"groups-claim"           yaml:"groups-claim"`
	AuthorizeParams      string             `json:"authorize-params"       yaml:"authorize-params"`
	Provider             string             `json:"provider"               yaml:"provider"`
	OpenVPNUsernameCEL   string             `json:"openvpn-username-cel"   yaml:"openvpn-username-cel"`
	Scopes               types.StringSlice  `json:"scopes"                 yaml:"scopes"`
	Validate             OAuth2Validate     `json:"validate"               yaml:"validate"`
	Refresh              OAuth2Refresh      `json:"refresh"                yaml:"refresh"`
	RefreshNonce         OAuth2RefreshNonce `json:"refresh-nonce"          yaml:"refresh-nonce"`
	AuthStyle            OAuth2AuthStyle    `json:"auth-style"             yaml:"auth-style"`
	Nonce                bool               `json:"nonce"                  yaml:"nonce"`
	PKCE                 bool               `json:"pkce"                   yaml:"pkce"`
	UserInfo             bool               `json:"user-info"              yaml:"user-info"`
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
	CEL                     string            `json:"cel"                        yaml:"cel"`
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

//goland:noinspection GoMixedReceiverTypes
func (c Config) String() string {
	jsonString, err := json.Marshal(c)
	if err != nil {
		return fmt.Sprintf("Config{error: %v}", err)
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
