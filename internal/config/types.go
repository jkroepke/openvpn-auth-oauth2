//nolint:lll
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
	BaseURL            types.URL      `flag:"baseurl"              json:"baseurl"              usage:"listen addr for client listener"                                                                                                                                      yaml:"baseurl"`
	AssetPath          types.FS       `flag:"assets-path"          json:"assets-path"          usage:"Custom path to the assets directory. Files in this directory will be served under /assets/ and having an higher priority than the embedded assets."                   yaml:"assets-path"`
	Template           types.Template `flag:"template"             json:"template"             usage:"Path to a HTML file which is displayed at the end of the screen. See https://github.com/jkroepke/openvpn-auth-oauth2/wiki/Layout-Customization for more information." yaml:"template"`
	Listen             string         `flag:"listen"               json:"listen"               usage:"listen addr for client listener"                                                                                                                                      yaml:"listen"`
	CertFile           string         `flag:"cert"                 json:"cert"                 usage:"Path to tls server certificate used for TLS listener."                                                                                                                yaml:"cert"`
	KeyFile            string         `flag:"key"                  json:"key"                  usage:"Path to tls server key used for TLS listener."                                                                                                                        yaml:"key"`
	Secret             types.Secret   `flag:"secret"               json:"secret"               usage:"Random generated secret for cookie encryption. Must be 16, 24 or 32 characters. If argument starts with file:// it reads the secret from a file."                     yaml:"secret"`
	TLS                bool           `flag:"tls"                  json:"tls"                  usage:"enable TLS listener"                                                                                                                                                  yaml:"tls"`
	Check              HTTPCheck      `json:"check"                yaml:"check"`
	EnableProxyHeaders bool           `flag:"enable-proxy-headers" json:"enable-proxy-headers" usage:"Use X-Forward-For http header for client ips"                                                                                                                         yaml:"enable-proxy-headers"`
	ShortURL           bool           `flag:"short-url"            json:"short-url"            usage:"Enable short URL. The URL which is used for initial authentication will be reduced to /?s=... instead of /oauth2/start?state=..."                                     yaml:"short-url"`
}

type HTTPCheck struct {
	IPAddr bool `flag:"ipaddr" json:"ipaddr" usage:"Check if client IP in http and VPN is equal" yaml:"ipaddr"`
}

type Log struct {
	Format      string     `flag:"format"        json:"format"        usage:"log format. json or console"                                                                 yaml:"format"`
	Level       slog.Level `flag:"level"         json:"level"         usage:"log level. Can be one of: debug, info, warn, error"                                          yaml:"level"`
	VPNClientIP bool       `flag:"vpn-client-ip" json:"vpn-client-ip" usage:"log IP of VPN client. Useful to have an identifier between OpenVPN and openvpn-auth-oauth2." yaml:"vpn-client-ip"`
}

type OpenVPN struct {
	Addr               types.URL          `flag:"addr"                 json:"addr"                 usage:"openvpn management interface addr. Must start with unix:// or tcp://"                                                                                                                                                                                                                                                       yaml:"addr"`
	Password           types.Secret       `flag:"password"             json:"password"             usage:"openvpn management interface password. If argument starts with file:// it reads the secret from a file."                                                                                                                                                                                                                    yaml:"password"`
	Bypass             OpenVPNBypass      `json:"bypass"               yaml:"bypass"`
	CommonName         OpenVPNCommonName  `json:"common-name"          yaml:"common-name"`
	Passthrough        OpenVPNPassthrough `json:"pass-through"         yaml:"pass-through"`
	ClientConfig       OpenVPNConfig      `json:"client-config"        yaml:"client-config"`
	AuthPendingTimeout time.Duration      `flag:"auth-pending-timeout" json:"auth-pending-timeout" usage:"How long OpenVPN server wait until user is authenticated"                                                                                                                                                                                                                                                                   yaml:"auth-pending-timeout"`
	CommandTimeout     time.Duration      `flag:"command-timeout"      json:"command-timeout"      usage:"Timeout for commands sent to the OpenVPN management interface."                                                                                                                                                                                                                                                             yaml:"command-timeout"`
	OverrideUsername   bool               `flag:"override-username"    json:"override-username"    usage:"Requires OpenVPN Server 2.7! If true, openvpn-auth-oauth2 use the override-username command to set the username in OpenVPN connection. This is useful to use real usernames in OpenVPN statistics. The username will be set after client configs are read. Read OpenVPN man page for limitations of the override-username." yaml:"override-username"`
	ReAuthentication   bool               `flag:"reauthentication"     json:"reauthentication"     usage:"If set to false, openvpn-auth-oauth2 rejects all re-authentication requests."                                                                                                                                                                                                                                               yaml:"reauthentication"`
	AuthTokenUser      bool               `flag:"auth-token-user"      json:"auth-token-user"      usage:"Override the username of a session with the username from the token by using auth-token-user, if the client username is empty"                                                                                                                                                                                              yaml:"auth-token-user"`
}

type OpenVPNBypass struct {
	CommonNames types.RegexpSlice `flag:"common-names" json:"common-names" usage:"Skip OAuth authentication for client certificate common names (CNs) matching any of the given regular expressions. Multiple expressions can be provided as a comma-separated list. Regular expressions are automatically anchored (^…$) by default, so \"client\" matches only \"client\". To allow partial matches, specify explicitly (e.g. \"client.*\")." yaml:"common-names"`
}
type OpenVPNConfig struct {
	Path         types.FS                     `flag:"path"          json:"path"          usage:"Path to the CCD directory. openvpn-auth-oauth2 will look for an file with an .conf suffix and returns the content back."                                yaml:"path"`
	TokenClaim   string                       `flag:"token-claim"   json:"token-claim"   usage:"If non-empty, the value of the token claim is used to lookup the configuration file in the CCD directory. If empty, the common name is used."           yaml:"token-claim"`
	UserSelector OpenVPNConfigProfileSelector `json:"user-selector" yaml:"user-selector"`
	Enabled      bool                         `flag:"enabled"       json:"enabled"       usage:"If true, openvpn-auth-oauth2 will read the CCD directory for additional configuration. This function mimic the client-config-dir directive in OpenVPN." yaml:"enabled"`
}

type OpenVPNConfigProfileSelector struct {
	StaticValues types.StringSlice `flag:"static-values" json:"static-values" usage:"Comma-separated list of static profile names that are always available in the profile selector UI. These profiles will be displayed as selectable options for all users."                                                                                                                                                                                                                                       yaml:"static-values"`
	Enabled      bool              `flag:"enabled"       json:"enabled"       usage:"If true, openvpn-auth-oauth2 will display a profile selection UI after OAuth2 authentication, allowing users to choose their client configuration profile. Profile options are populated from openvpn.client-config.user-selector.static-values and openvpn.client-config.token-claim (if configured). After selection, the chosen profile name is used to lookup the configuration file in the CCD directory." yaml:"enabled"`
}

type OpenVPNCommonName struct {
	EnvironmentVariableName string                `flag:"environment-variable-name" json:"environment-variable-name" usage:"Name of the environment variable in the OpenVPN management interface which contains the common name. If username-as-common-name is enabled, this should be set to 'username' to use the username as common name. Other values like 'X509_0_emailAddress' are supported. See https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/#environmental-variables for more information." yaml:"environment-variable-name"`
	Mode                    OpenVPNCommonNameMode `flag:"mode"                      json:"mode"                      usage:"If common names are too long, use md5/sha1 to hash them or omit to skip them. If omit, oauth2.validate.common-name does not work anymore. Values: [plain,omit]"                                                                                                                                                                                                                                      yaml:"mode"`
}

type OAuth2 struct {
	Endpoints            OAuth2Endpoints    `json:"endpoint"               yaml:"endpoint"`
	Issuer               types.URL          `flag:"issuer"                 json:"issuer"                 usage:"oauth2 issuer"                                                                                                                                                                                                                             yaml:"issuer"`
	Client               OAuth2Client       `json:"client"                 yaml:"client"`
	OpenVPNUsernameClaim string             `flag:"openvpn-username-claim" json:"openvpn-username-claim" usage:"The claim name in the ID Token which should be used as username in OpenVPN. If empty, the common name is used."                                                                                                                            yaml:"openvpn-username-claim"`
	GroupsClaim          string             `flag:"groups-claim"           json:"groups-claim"           usage:"Defines the claim name in the ID Token which contains the user groups."                                                                                                                                                                    yaml:"groups-claim"`
	AuthorizeParams      string             `flag:"authorize-params"       json:"authorize-params"       usage:"additional url query parameter to authorize endpoint"                                                                                                                                                                                      yaml:"authorize-params"`
	Provider             string             `flag:"provider"               json:"provider"               usage:"oauth2 provider"                                                                                                                                                                                                                           yaml:"provider"`
	OpenVPNUsernameCEL   string             `flag:"openvpn-username-cel"   json:"openvpn-username-cel"   usage:"CEL expression to extract the username from the token. The expression must evaluate to a string value. Example: oauth2TokenClaims.sub Note: oauth2.openvpn-username-claim and oauth2.openvpn-username-cel cannot be set at the same time." yaml:"openvpn-username-cel"`
	Scopes               types.StringSlice  `flag:"scopes"                 json:"scopes"                 usage:"oauth2 token scopes. Defaults depends on oauth2.provider. Comma separated list. Example: openid,profile,email"                                                                                                                             yaml:"scopes"`
	Validate             OAuth2Validate     `json:"validate"               yaml:"validate"`
	Refresh              OAuth2Refresh      `json:"refresh"                yaml:"refresh"`
	RefreshNonce         OAuth2RefreshNonce `flag:"refresh-nonce"          json:"refresh-nonce"          usage:"Controls nonce behavior on refresh token requests. Options: auto (try with nonce, retry without on error), empty (always use empty nonce), equal (use same nonce as initial auth)."                                                        yaml:"refresh-nonce"`
	AuthStyle            OAuth2AuthStyle    `flag:"auth-style"             json:"auth-style"             usage:"Auth style represents how requests for tokens are authenticated to the server. Possible values: AuthStyleAutoDetect, AuthStyleInParams, AuthStyleInHeader. See https://pkg.go.dev/golang.org/x/oauth2#AuthStyle"                           yaml:"auth-style"`
	Nonce                bool               `flag:"nonce"                  json:"nonce"                  usage:"If true, a nonce will be defined on the auth URL which is expected inside the token."                                                                                                                                                      yaml:"nonce"`
	PKCE                 bool               `flag:"pkce"                   json:"pkce"                   usage:"If true, Proof Key for Code Exchange (PKCE) RFC 7636 is used for token exchange."                                                                                                                                                          yaml:"pkce"`
	UserInfo             bool               `flag:"user-info"              json:"user-info"              usage:"If true, openvpn-auth-oauth2 uses the OIDC UserInfo endpoint to fetch additional information about the user (e.g. groups)."                                                                                                                yaml:"user-info"`
}

type OAuth2Client struct {
	ID           string       `flag:"id"             json:"id"             usage:"oauth2 client id"                                                                                                                        yaml:"id"`
	Secret       types.Secret `flag:"secret"         json:"secret"         usage:"oauth2 client secret. If argument starts with file:// it reads the secret from a file."                                                  yaml:"secret"`
	PrivateKey   types.Secret `flag:"private-key"    json:"private-key"    usage:"oauth2 client private key. Secure alternative to oauth2.client.secret. If argument starts with file:// it reads the secret from a file." yaml:"private-key"`
	PrivateKeyID string       `flag:"private-key-id" json:"private-key-id" usage:"oauth2 client private key id. If specified, JWT assertions will be generated with the specific kid header."                              yaml:"private-key-id"`
}

type OAuth2Endpoints struct {
	Discovery types.URL `flag:"discovery" json:"discovery" usage:"The flag is used to set a custom OAuth2 discovery URL. This URL retrieves the provider's configuration details." yaml:"discovery"`
	Auth      types.URL `flag:"auth"      json:"auth"      usage:"The flag is used to specify a custom OAuth2 authorization endpoint."                                             yaml:"auth"`
	Token     types.URL `flag:"token"     json:"token"     usage:"The flag is used to specify a custom OAuth2 token endpoint."                                                     yaml:"token"`
}

type OAuth2Validate struct {
	CommonName              string            `flag:"common-name"                json:"common-name"                usage:"validate common_name from OpenVPN with ID Token claim. For example: preferred_username or sub"                                                                       yaml:"common-name"`
	CEL                     string            `flag:"cel"                        json:"cel"                        usage:"CEL expression for custom token validation. The expression must evaluate to a boolean value. Example: openVPNUserCommonName == oauth2TokenClaims.preferred_username" yaml:"cel"`
	Acr                     types.StringSlice `flag:"acr"                        json:"acr"                        usage:"oauth2 required acr values. Comma separated list. Example: phr,phrh"                                                                                                 yaml:"acr"`
	Groups                  types.StringSlice `flag:"groups"                     json:"groups"                     usage:"oauth2 required user groups. If multiple groups are configured, the user needs to be least in one group. Comma separated list. Example: group1,group2,group3"        yaml:"groups"`
	Roles                   types.StringSlice `flag:"roles"                      json:"roles"                      usage:"oauth2 required user roles. If multiple role are configured, the user needs to be least in one role. Comma separated list. Example: role1,role2,role3"               yaml:"roles"`
	IPAddr                  bool              `flag:"ipaddr"                     json:"ipaddr"                     usage:"validate client ipaddr between VPN and OIDC token"                                                                                                                   yaml:"ipaddr"`
	Issuer                  bool              `flag:"issuer"                     json:"issuer"                     usage:"validate issuer from OIDC discovery"                                                                                                                                 yaml:"issuer"`
	CommonNameCaseSensitive bool              `flag:"common-name-case-sensitive" json:"common-name-case-sensitive" usage:"If true, openvpn-auth-oauth2 will validate the common case in sensitive mode"                                                                                        yaml:"common-name-case-sensitive"`
}

type OAuth2Refresh struct {
	Secret       types.Secret  `flag:"secret"         json:"secret"         usage:"Required, if oauth2.refresh.enabled=true. Random generated secret for token encryption. Must be 16, 24 or 32 characters. If argument starts with file:// it reads the secret from a file." yaml:"secret"`
	Expires      time.Duration `flag:"expires"        json:"expires"        usage:"TTL of stored oauth2 token."                                                                                                                                                               yaml:"expires"`
	Enabled      bool          `flag:"enabled"        json:"enabled"        usage:"If true, openvpn-auth-oauth2 stores refresh tokens and will use it do an non-interaction reauth."                                                                                          yaml:"enabled"`
	UseSessionID bool          `flag:"use-session-id" json:"use-session-id" usage:"If true, openvpn-auth-oauth2 will use the session_id to refresh sessions on initial auth. Requires 'auth-token-gen [lifetime] external-auth' on OpenVPN server."                           yaml:"use-session-id"`
	ValidateUser bool          `flag:"validate-user"  json:"validate-user"  usage:"If true, openvpn-auth-oauth2 will validate the user against the OIDC provider on each refresh. Usefully, if API limits are exceeded or OIDC provider can't deliver an refresh token."      yaml:"validate-user"`
}

type OpenVPNPassthrough struct {
	Address     types.URL    `flag:"address"      json:"address"      usage:"The address of the pass-through socket. Must start with unix:// or tcp://"                                                                         yaml:"address"`
	Password    types.Secret `flag:"password"     json:"password"     usage:"The password for the pass-through socket. If argument starts with file:// it reads the secret from a file."                                        yaml:"password"`
	SocketGroup string       `flag:"socket-group" json:"socket-group" usage:"The group for the pass-through socket. Used only, if openvpn.pass-through.address starts with unix:// If empty, the group of the process is used." yaml:"socket-group"`
	SocketMode  uint         `flag:"socket-mode"  json:"socket-mode"  usage:"The unix file permission mode for the pass-through socket. Used only, if openvpn.pass-through.address starts with unix://"                         yaml:"socket-mode"`
	Enabled     bool         `flag:"enabled"      json:"enabled"      usage:"If true, openvpn-auth-oauth2 will setup a pass-through socket for the OpenVPN management interface."                                               yaml:"enabled"`
}

type Debug struct {
	Listen string `flag:"listen" json:"listen" usage:"listen address for go profiling endpoint"                     yaml:"listen"`
	Pprof  bool   `flag:"pprof"  json:"pprof"  usage:"Enables go profiling endpoint. This should be never exposed." yaml:"pprof"`
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
