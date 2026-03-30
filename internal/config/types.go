//nolint:lll
package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"golang.org/x/oauth2"
)

type Config struct {
	HTTP    HTTP    `json:"http"    mapstructure:"http"    yaml:"http"`
	Debug   Debug   `json:"debug"   mapstructure:"debug"   yaml:"debug"`
	Log     Log     `json:"log"     mapstructure:"log"     yaml:"log"`
	OAuth2  OAuth2  `json:"oauth2"  mapstructure:"oauth2"  yaml:"oauth2"`
	OpenVPN OpenVPN `json:"openvpn" mapstructure:"openvpn" yaml:"openvpn"`
}

type HTTP struct {
	BaseURL            *url.URL       `help:"listen addr for client listener"                                  json:"baseurl"              mapstructure:"baseurl"              yaml:"baseurl"`
	AssetPath          types.FS       `help:"Custom path to static assets served under /assets/."              json:"assets-path"          mapstructure:"assets-path"          yaml:"assets-path"`
	Template           types.Template `help:"Path to HTML template shown after authentication."                json:"template"             mapstructure:"template"             yaml:"template"`
	Listen             string         `help:"listen addr for client listener"                                  json:"listen"               mapstructure:"listen"               yaml:"listen"`
	CertFile           string         `help:"Path to TLS server certificate."                                  json:"cert"                 mapstructure:"cert"                 yaml:"cert"`
	KeyFile            string         `help:"Path to TLS server key."                                          json:"key"                  mapstructure:"key"                  yaml:"key"`
	Secret             types.Secret   `help:"Cookie encryption secret (16, 24, or 32 chars, or file:// path)." json:"secret"               mapstructure:"secret"               yaml:"secret"`
	TLS                bool           `help:"enable TLS listener"                                              json:"tls"                  mapstructure:"tls"                  yaml:"tls"`
	Check              HTTPCheck      `json:"check"                                                            mapstructure:"check"        yaml:"check"`
	EnableProxyHeaders bool           `help:"Use X-Forwarded-For header for client IPs."                       json:"enable-proxy-headers" mapstructure:"enable-proxy-headers" yaml:"enable-proxy-headers"`
	ShortURL           bool           `help:"Use short auth URL /?s=... instead of /oauth2/start?state=..."    json:"short-url"            mapstructure:"short-url"            yaml:"short-url"`
}

type HTTPCheck struct {
	IPAddr bool `help:"Check whether HTTP and VPN client IPs match." json:"ipaddr" mapstructure:"ipaddr" yaml:"ipaddr"`
}

type Log struct {
	Format      string     `help:"log format: json or console"                            json:"format"        mapstructure:"format"        yaml:"format"`
	Level       slog.Level `help:"log level: debug, info, warn, or error"                 json:"level"         mapstructure:"level"         yaml:"level"`
	VPNClientIP bool       `help:"Log VPN client IP for correlation with OpenVPN events." json:"vpn-client-ip" mapstructure:"vpn-client-ip" yaml:"vpn-client-ip"`
}

type OpenVPN struct {
	Addr               *url.URL           `help:"OpenVPN management interface address (unix:// or tcp://)."     json:"addr"                    mapstructure:"addr"                 yaml:"addr"`
	Password           types.Secret       `help:"OpenVPN management interface password (supports file://)."     json:"password"                mapstructure:"password"             yaml:"password"`
	Bypass             OpenVPNBypass      `json:"bypass"                                                        mapstructure:"bypass"          yaml:"bypass"`
	CommonName         OpenVPNCommonName  `json:"common-name"                                                   mapstructure:"common-name"     yaml:"common-name"`
	Passthrough        OpenVPNPassthrough `json:"pass-through"                                                  mapstructure:"pass-through"    yaml:"pass-through"`
	ClientConfig       OpenVPNConfig      `json:"client-config"                                                 mapstructure:"client-config"   yaml:"client-config"`
	AuthPendingTimeout time.Duration      `help:"Maximum time OpenVPN waits for browser authentication."        json:"auth-pending-timeout"    mapstructure:"auth-pending-timeout" yaml:"auth-pending-timeout"`
	CommandTimeout     time.Duration      `json:"command-timeout"                                               mapstructure:"command-timeout" yaml:"command-timeout"`
	OverrideUsername   bool               `help:"Use OpenVPN 2.7 override-username to set connection username." json:"override-username"       mapstructure:"override-username"    yaml:"override-username"`
	ReAuthentication   bool               `help:"If false, reject all re-authentication requests."              json:"reauthentication"        mapstructure:"reauthentication"     yaml:"reauthentication"`
	AuthTokenUser      bool               `help:"Use token username when OpenVPN client username is empty."     json:"auth-token-user"         mapstructure:"auth-token-user"      yaml:"auth-token-user"`
}

type OpenVPNBypass struct {
	CommonNames types.RegexpSlice `help:"Skip OAuth for certificate CNs matching regex values." json:"common-names" mapstructure:"common-names" yaml:"common-names"`
}

type OpenVPNConfig struct {
	Path         types.FS                     `help:"Path to client-config-dir (CCD)."                                    json:"path"                  mapstructure:"path"        yaml:"path"`
	TokenClaim   string                       `help:"Token claim used to resolve CCD profile; falls back to common name." json:"token-claim"           mapstructure:"token-claim" yaml:"token-claim"`
	UserSelector OpenVPNConfigProfileSelector `json:"user-selector"                                                       mapstructure:"user-selector" yaml:"user-selector"`
	Enabled      bool                         `help:"Enable CCD lookup compatible with OpenVPN client-config-dir."        json:"enabled"               mapstructure:"enabled"     yaml:"enabled"`
}

type OpenVPNConfigProfileSelector struct {
	StaticValues []string `help:"Static profile names shown in profile selector UI." json:"static-values" mapstructure:"static-values" yaml:"static-values"`
	Enabled      bool     `help:"Show profile selector UI after OAuth2 login."       json:"enabled"       mapstructure:"enabled"       yaml:"enabled"`
}

type OpenVPNCommonName struct {
	EnvironmentVariableName string                `help:"OpenVPN env var that contains the client common name." json:"environment-variable-name" mapstructure:"environment-variable-name" yaml:"environment-variable-name"`
	Mode                    OpenVPNCommonNameMode `help:"Common-name mode: plain or omit."                      json:"mode"                      mapstructure:"mode"                      yaml:"mode"`
}

type OAuth2 struct {
	Endpoints            OAuth2Endpoints    `json:"endpoint"                                                          mapstructure:"endpoint"       yaml:"endpoint"`
	Issuer               *url.URL           `help:"oauth2 issuer"                                                     json:"issuer"                 mapstructure:"issuer"                 yaml:"issuer"`
	Client               OAuth2Client       `json:"client"                                                            mapstructure:"client"         yaml:"client"`
	OpenVPNUsernameClaim string             `help:"ID token claim used as OpenVPN username; empty keeps common name." json:"openvpn-username-claim" mapstructure:"openvpn-username-claim" yaml:"openvpn-username-claim"`
	GroupsClaim          string             `help:"ID token claim name that contains user groups."                    json:"groups-claim"           mapstructure:"groups-claim"           yaml:"groups-claim"`
	AuthorizeParams      string             `help:"Additional query parameters for OAuth2 authorize endpoint."        json:"authorize-params"       mapstructure:"authorize-params"       yaml:"authorize-params"`
	Provider             string             `help:"oauth2 provider"                                                   json:"provider"               mapstructure:"provider"               yaml:"provider"`
	OpenVPNUsernameCEL   string             `help:"CEL expression that resolves OpenVPN username from token claims."  json:"openvpn-username-cel"   mapstructure:"openvpn-username-cel"   yaml:"openvpn-username-cel"`
	Scopes               []string           `help:"OAuth2 scopes (comma-separated)."                                  json:"scopes"                 mapstructure:"scopes"                 yaml:"scopes"`
	Validate             OAuth2Validate     `json:"validate"                                                          mapstructure:"validate"       yaml:"validate"`
	Refresh              OAuth2Refresh      `json:"refresh"                                                           mapstructure:"refresh"        yaml:"refresh"`
	RefreshNonce         OAuth2RefreshNonce `help:"Refresh nonce mode: auto, empty, or equal."                        json:"refresh-nonce"          mapstructure:"refresh-nonce"          yaml:"refresh-nonce"`
	AuthStyle            OAuth2AuthStyle    `help:"OAuth2 auth style: auto-detect, in params, or in header."          json:"auth-style"             mapstructure:"auth-style"             yaml:"auth-style"`
	Nonce                bool               `help:"Enable nonce validation in OIDC flow."                             json:"nonce"                  mapstructure:"nonce"                  yaml:"nonce"`
	PKCE                 bool               `help:"Enable PKCE for authorization code flow."                          json:"pkce"                   mapstructure:"pkce"                   yaml:"pkce"`
	UserInfo             bool               `help:"Fetch extra claims from OIDC UserInfo endpoint."                   json:"user-info"              mapstructure:"user-info"              yaml:"user-info"`
}

type OAuth2Client struct {
	ID           string       `help:"oauth2 client id"                                          json:"id"             mapstructure:"id"             yaml:"id"`
	Secret       types.Secret `help:"oauth2 client secret (supports file://)."                  json:"secret"         mapstructure:"secret"         yaml:"secret"`
	PrivateKey   types.Secret `help:"oauth2 client private key (alternative to client secret)." json:"private-key"    mapstructure:"private-key"    yaml:"private-key"`
	PrivateKeyID string       `help:"oauth2 client private key id (kid header)."                json:"private-key-id" mapstructure:"private-key-id" yaml:"private-key-id"`
}

type OAuth2Endpoints struct {
	Discovery *url.URL `help:"Custom OAuth2 discovery endpoint."     json:"discovery" mapstructure:"discovery" yaml:"discovery"`
	Auth      *url.URL `help:"Custom OAuth2 authorization endpoint." json:"auth"      mapstructure:"auth"      yaml:"auth"`
	Token     *url.URL `help:"Custom OAuth2 token endpoint."         json:"token"     mapstructure:"token"     yaml:"token"`
}

type OAuth2Validate struct {
	CommonName              string   `help:"OpenVPN common_name claim to validate (for example preferred_username)." json:"common-name"                mapstructure:"common-name"                yaml:"common-name"`
	CEL                     string   `help:"CEL expression for custom token validation."                             json:"cel"                        mapstructure:"cel"                        yaml:"cel"`
	Acr                     []string `help:"Required ACR values (comma-separated)."                                  json:"acr"                        mapstructure:"acr"                        yaml:"acr"`
	Groups                  []string `help:"Required user groups (match any)."                                       json:"groups"                     mapstructure:"groups"                     yaml:"groups"`
	Roles                   []string `help:"Required user roles (match any)."                                        json:"roles"                      mapstructure:"roles"                      yaml:"roles"`
	IPAddr                  bool     `help:"Validate client IP between VPN session and token."                       json:"ipaddr"                     mapstructure:"ipaddr"                     yaml:"ipaddr"`
	Issuer                  bool     `help:"Validate token issuer against discovery issuer."                         json:"issuer"                     mapstructure:"issuer"                     yaml:"issuer"`
	CommonNameCaseSensitive bool     `help:"Use case-sensitive common_name comparison."                              json:"common-name-case-sensitive" mapstructure:"common-name-case-sensitive" yaml:"common-name-case-sensitive"`
}

type OAuth2Refresh struct {
	Secret       types.Secret  `help:"Token encryption secret for refresh storage (supports file://)." json:"secret"         mapstructure:"secret"         yaml:"secret"`
	Expires      time.Duration `help:"TTL for stored refresh tokens."                                  json:"expires"        mapstructure:"expires"        yaml:"expires"`
	Enabled      bool          `help:"Enable non-interactive reauth via refresh tokens."               json:"enabled"        mapstructure:"enabled"        yaml:"enabled"`
	UseSessionID bool          `help:"Use OpenVPN session_id for refresh after initial auth."          json:"use-session-id" mapstructure:"use-session-id" yaml:"use-session-id"`
	ValidateUser bool          `help:"Re-validate user with provider during refresh."                  json:"validate-user"  mapstructure:"validate-user"  yaml:"validate-user"`
}

type OpenVPNPassthrough struct {
	Address     *url.URL     `help:"Pass-through socket address (unix:// or tcp://)."            json:"address"      mapstructure:"address"      yaml:"address"`
	Password    types.Secret `help:"Pass-through socket password (supports file://)."            json:"password"     mapstructure:"password"     yaml:"password"`
	SocketGroup string       `help:"Unix group for pass-through socket; process group if empty." json:"socket-group" mapstructure:"socket-group" yaml:"socket-group"`
	SocketMode  uint         `help:"Unix permission mode for pass-through socket."               json:"socket-mode"  mapstructure:"socket-mode"  yaml:"socket-mode"`
	Enabled     bool         `help:"Enable OpenVPN management pass-through socket."              json:"enabled"      mapstructure:"enabled"      yaml:"enabled"`
}

type Debug struct {
	Listen string `help:"listen address for go profiling endpoint"          json:"listen" mapstructure:"listen" yaml:"listen"`
	Pprof  bool   `help:"Enable Go pprof endpoint; do not expose publicly." json:"pprof"  mapstructure:"pprof"  yaml:"pprof"`
}

type OpenVPNCommonNameMode int

const (
	CommonNameModePlain OpenVPNCommonNameMode = iota
	CommonNameModeOmit
)

const CommonNameModeOmitValue = "-"

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
