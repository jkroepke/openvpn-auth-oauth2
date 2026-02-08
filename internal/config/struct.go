//nolint:lll
package config

import (
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/url"
	"regexp"
	"text/template"
	"time"
)

type Config struct {
	ConfigFile string  `json:"config"  kong:"help='path to one .yaml config file',type='path'" yaml:"config"`
	HTTP       HTTP    `json:"http"    kong:"embed,prefix='http.'"                             yaml:"http"`
	Debug      Debug   `json:"debug"   kong:"embed,prefix='debug.'"                            yaml:"debug"`
	Log        Log     `json:"log"     kong:"embed,prefix='log.'"                              yaml:"log"`
	OAuth2     OAuth2  `json:"oauth2"  kong:"embed,group:'oauth2',prefix='oauth2.'"            yaml:"oauth2"`
	OpenVPN    OpenVPN `json:"openvpn" kong:"embed,prefix='openvpn.'"                          yaml:"openvpn"`
	Version    bool    `json:"-"       kong:"help='show version'"                              yaml:"-"`
}

type HTTP struct {
	BaseURL            *url.URL           `json:"baseurl"              kong:"help='listen addr for client listener',env='CONFIG_HTTP_BASEURL'"                                                                                                                                       yaml:"baseurl"`
	AssetPath          fs.FS              `json:"assets-path"          kong:"help='Custom path to the assets directory. Files in this directory will be served under /assets/ and having an higher priority than the embedded assets.',env='CONFIG_HTTP_ASSETS__PATH'"               yaml:"assets-path"`
	Template           *template.Template `json:"template"             kong:"help='Path to a HTML file which is displayed at the end of the screen. See https://github.com/jkroepke/openvpn-auth-oauth2/wiki/Layout-Customization for more information.',env='CONFIG_HTTP_TEMPLATE'" yaml:"template"`
	Listen             string             `json:"listen"               kong:"help='listen addr for client listener',env='CONFIG_HTTP_LISTEN'"                                                                                                                                        yaml:"listen"`
	CertFile           string             `json:"cert"                 kong:"help='Path to tls server certificate used for TLS listener.',env='CONFIG_HTTP_CERT'"                                                                                                                    yaml:"cert"`
	KeyFile            string             `json:"key"                  kong:"help='Path to tls server key used for TLS listener.',env='CONFIG_HTTP_KEY'"                                                                                                                             yaml:"key"`
	Secret             Secret             `json:"secret"               kong:"help='Random generated secret for cookie encryption. Must be 16, 24 or 32 characters. If argument starts with file:// it reads the secret from a file.',required='',env='CONFIG_HTTP_SECRET'"           yaml:"secret"`
	TLS                bool               `json:"tls"                  kong:"help='enable TLS listener',env='CONFIG_HTTP_TLS'"                                                                                                                                                       yaml:"tls"`
	Check              HTTPCheck          `json:"check"                kong:"embed,prefix='check.'"                                                                                                                                                                                  yaml:"check"`
	EnableProxyHeaders bool               `json:"enable-proxy-headers" kong:"help='Use X-Forward-For http header for client ips',env='CONFIG_HTTP_ENABLE__PROXY__HEADERS'"                                                                                                           yaml:"enable-proxy-headers"`
	ShortURL           bool               `json:"short-url"            kong:"help='Enable short URL. The URL which is used for initial authentication will be reduced to /?s=... instead of /oauth2/start?state=...',env='CONFIG_HTTP_SHORT__URL'"                                   yaml:"short-url"`
}

type HTTPCheck struct {
	IPAddr bool `json:"ipaddr" kong:"help='Check if client IP in http and VPN is equal',env='CONFIG_HTTP_CHECK_IPADDR'" yaml:"ipaddr"`
}

type Log struct {
	Format      string     `json:"format"        kong:"help='log format. json or console',enum='json,console',env='CONFIG_LOG_FORMAT'"                                                      yaml:"format"`
	Level       slog.Level `json:"level"         kong:"help='log level. Can be one of: debug, info, warn, error',env='CONFIG_LOG_LEVEL'"                                                    yaml:"level"`
	VPNClientIP bool       `json:"vpn-client-ip" kong:"help='log IP of VPN client. Useful to have an identifier between OpenVPN and openvpn-auth-oauth2.',env='CONFIG_LOG_VPN__CLIENT__IP'" yaml:"vpn-client-ip"`
}

type OpenVPN struct {
	Addr               *url.URL           `json:"addr"                 kong:"help='openvpn management interface addr. Must start with unix:// or tcp://',env='CONFIG_OPENVPN_ADDR'"                                                                                                                                                                                                                                                                     yaml:"addr"`
	Password           Secret             `json:"password"             kong:"help='openvpn management interface password. If argument starts with file:// it reads the secret from a file.',env='CONFIG_OPENVPN_PASSWORD'"                                                                                                                                                                                                                              yaml:"password"`
	Bypass             OpenVPNBypass      `json:"bypass"               kong:"embed,prefix='bypass.'"                                                                                                                                                                                                                                                                                                                                                    yaml:"bypass"`
	CommonName         OpenVPNCommonName  `json:"common-name"          kong:"embed,prefix='common-name.'"                                                                                                                                                                                                                                                                                                                                               yaml:"common-name"`
	Passthrough        OpenVPNPassthrough `json:"pass-through"         kong:"embed,prefix='pass-through.'"                                                                                                                                                                                                                                                                                                                                              yaml:"pass-through"`
	ClientConfig       OpenVPNConfig      `json:"client-config"        kong:"embed,prefix='client-config.'"                                                                                                                                                                                                                                                                                                                                             yaml:"client-config"`
	AuthPendingTimeout time.Duration      `json:"auth-pending-timeout" kong:"help='How long OpenVPN server wait until user is authenticated',env='CONFIG_OPENVPN_AUTH__PENDING__TIMEOUT'"                                                                                                                                                                                                                                                               yaml:"auth-pending-timeout"`
	CommandTimeout     time.Duration      `json:"command-timeout"      kong:"help='Command timeout for OpenVPN management interface',env='CONFIG_OPENVPN_COMMAND__TIMEOUT'"                                                                                                                                                                                                                                                                             yaml:"command-timeout"`
	OverrideUsername   bool               `json:"override-username"    kong:"help='Requires OpenVPN Server 2.7! If true, openvpn-auth-oauth2 use the override-username command to set the username in OpenVPN connection. This is useful to use real usernames in OpenVPN statistics. The username will be set after client configs are read. Read OpenVPN man page for limitations of the override-username.',env='CONFIG_OPENVPN_OVERRIDE__USERNAME'" yaml:"override-username"`
	ReAuthentication   bool               `json:"reauthentication"     kong:"help='If set to false, openvpn-auth-oauth2 rejects all re-authentication requests.',env='CONFIG_OPENVPN_REAUTHENTICATION'"                                                                                                                                                                                                                                                 yaml:"reauthentication"`
	AuthTokenUser      bool               `json:"auth-token-user"      kong:"help='Override the username of a session with the username from the token by using auth-token-user, if the client username is empty',env='CONFIG_OPENVPN_AUTH__TOKEN__USER'"                                                                                                                                                                                               yaml:"auth-token-user"`
}

type OpenVPNBypass struct {
	CommonNames []*regexp.Regexp `json:"common-names" kong:"help='Skip OAuth authentication for client certificate common names (CNs) matching any of the given regular expressions. Multiple expressions can be provided as a comma-separated list. Regular expressions are automatically anchored (^…$) by default, so \"client\" matches only \"client\". To allow partial matches, specify explicitly (e.g. \"client.*\").',env='CONFIG_OPENVPN_BYPASS_COMMON__NAMES'" yaml:"common-names"`
}
type OpenVPNConfig struct {
	Path         fs.FS                        `json:"path"          kong:"help='Path to the CCD directory. openvpn-auth-oauth2 will look for an file with an .conf suffix and returns the content back.',env='CONFIG_OPENVPN_CLIENT__CONFIG_PATH'"                                   yaml:"path"`
	TokenClaim   string                       `json:"token-claim"   kong:"help='If non-empty, the value of the token claim is used to lookup the configuration file in the CCD directory. If empty, the common name is used.',env='CONFIG_OPENVPN_CLIENT__CONFIG_TOKEN__CLAIM'"      yaml:"token-claim"`
	UserSelector OpenVPNConfigProfileSelector `json:"user-selector" kong:"embed,prefix='user-selector.'"                                                                                                                                                                             yaml:"user-selector"`
	Enabled      bool                         `json:"enabled"       kong:"help='If true, openvpn-auth-oauth2 will read the CCD directory for additional configuration. This function mimic the client-config-dir directive in OpenVPN.',env='CONFIG_OPENVPN_CLIENT__CONFIG_ENABLED'" yaml:"enabled"`
}

type OpenVPNConfigProfileSelector struct {
	StaticValues []string `json:"static-values" kong:"help='Comma-separated list of static profile names that are always available in the profile selector UI. These profiles will be displayed as selectable options for all users.',env='CONFIG_OPENVPN_CLIENT__CONFIG_USER__SELECTOR_STATIC__VALUES'"                                                                                                                                                                                                                                yaml:"static-values"`
	Enabled      bool     `json:"enabled"       kong:"help='If true, openvpn-auth-oauth2 will display a profile selection UI after OAuth2 authentication, allowing users to choose their client configuration profile. Profile options are populated from openvpn.client-config.user-selector.static-values and openvpn.client-config.token-claim (if configured). After selection, the chosen profile name is used to lookup the configuration file in the CCD directory.',env='CONFIG_OPENVPN_CLIENT__CONFIG_USER__SELECTOR_ENABLED'" yaml:"enabled"`
}

type OpenVPNCommonName struct {
	EnvironmentVariableName string                `json:"environment-variable-name" kong:"help='Name of the environment variable in the OpenVPN management interface which contains the common name. If username-as-common-name is enabled, this should be set to \\'username\\' to use the username as common name. Other values like \\'X509_0_emailAddress\\' are supported. See https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/#environmental-variables for more information.',env='CONFIG_OPENVPN_COMMON__NAME_ENVIRONMENT__VARIABLE__NAME'" yaml:"environment-variable-name"`
	Mode                    OpenVPNCommonNameMode `json:"mode"                      kong:"help='If common names are too long, use md5/sha1 to hash them or omit to skip them. If omit, oauth2.validate.common-name does not work anymore.',enum='plain,omit',env='CONFIG_OPENVPN_COMMON__NAME_MODE'"                                                                                                                                                                                                                                                                        yaml:"mode"`
}

type OAuth2 struct {
	Endpoints            OAuth2Endpoints    `json:"endpoint"               kong:"embed,prefix='endpoint.'"                                                                                                                                                                                                                                                                    yaml:"endpoint"`
	Issuer               *url.URL           `json:"issuer"                 kong:"help='oauth2 issuer',required='',env='CONFIG_OAUTH2_ISSUER'"                                                                                                                                                                                                                                 yaml:"issuer"`
	Client               OAuth2Client       `json:"client"                 kong:"embed,prefix='client.'"                                                                                                                                                                                                                                                                      yaml:"client"`
	OpenVPNUsernameClaim string             `json:"openvpn-username-claim" kong:"help='The claim name in the ID Token which should be used as username in OpenVPN. If empty, the common name is used.',env='CONFIG_OAUTH2_OPENVPN__USERNAME__CLAIM'"                                                                                                                          yaml:"openvpn-username-claim"`
	GroupsClaim          string             `json:"groups-claim"           kong:"help='Defines the claim name in the ID Token which contains the user groups.',env='CONFIG_OAUTH2_GROUPS__CLAIM'"                                                                                                                                                                             yaml:"groups-claim"`
	AuthorizeParams      string             `json:"authorize-params"       kong:"help='additional url query parameter to authorize endpoint',env='CONFIG_OAUTH2_AUTHORIZE__PARAMS'"                                                                                                                                                                                           yaml:"authorize-params"`
	Provider             string             `json:"provider"               kong:"help='oauth2 provider',env='CONFIG_OAUTH2_PROVIDER'"                                                                                                                                                                                                                                         yaml:"provider"`
	OpenVPNUsernameCEL   string             `json:"openvpn-username-cel"   kong:"help='CEL expression to extract the username from the token. The expression must evaluate to a string value. Example: oauth2TokenClaims.sub Note: oauth2.openvpn-username-claim and oauth2.openvpn-username-cel cannot be set at the same time.',env='CONFIG_OAUTH2_OPENVPN__USERNAME__CEL'" yaml:"openvpn-username-cel"`
	Scopes               []string           `json:"scopes"                 kong:"help='oauth2 token scopes. Defaults depends on oauth2.provider. Comma separated list. Example: openid,profile,email',env='CONFIG_OAUTH2_SCOPES'"                                                                                                                                             yaml:"scopes"`
	Validate             OAuth2Validate     `json:"validate"               kong:"embed,prefix='validate.'"                                                                                                                                                                                                                                                                    yaml:"validate"`
	Refresh              OAuth2Refresh      `json:"refresh"                kong:"embed,prefix='refresh.'"                                                                                                                                                                                                                                                                     yaml:"refresh"`
	RefreshNonce         OAuth2RefreshNonce `json:"refresh-nonce"          kong:"help='Controls nonce behavior on refresh token requests. Options: auto (try with nonce, retry without on error), empty (always use empty nonce), equal (use same nonce as initial auth).'enum='auto,empty,equal',env='CONFIG_OAUTH2_REFRESH__NONCE'"                                         yaml:"refresh-nonce"`
	AuthStyle            OAuth2AuthStyle    `json:"auth-style"             kong:"help='Auth style represents how requests for tokens are authenticated to the server. See https://pkg.go.dev/golang.org/x/oauth2#AuthStyle',enum='AuthStyleAutoDetect,AuthStyleInParams,AuthStyleInHeader',env='CONFIG_OAUTH2_AUTH__STYLE'"                                                   yaml:"auth-style"`
	Nonce                bool               `json:"nonce"                  kong:"help='If true, a nonce will be defined on the auth URL which is expected inside the token.',env='CONFIG_OAUTH2_NONCE'"                                                                                                                                                                       yaml:"nonce"`
	PKCE                 bool               `json:"pkce"                   kong:"help='If true, Proof Key for Code Exchange (PKCE) RFC 7636 is used for token exchange.',env='CONFIG_OAUTH2_PKCE'"                                                                                                                                                                            yaml:"pkce"`
	UserInfo             bool               `json:"user-info"              kong:"help='If true, openvpn-auth-oauth2 uses the OIDC UserInfo endpoint to fetch additional information about the user (e.g. groups).',env='CONFIG_OAUTH2_USER__INFO'"                                                                                                                            yaml:"user-info"`
}

type OAuth2Client struct {
	ID           string `json:"id"             kong:"help='oauth2 client id',required='',env='CONFIG_OAUTH2_CLIENT_ID'"                                                                                                                                                      yaml:"id"`
	Secret       Secret `json:"secret"         kong:"help='oauth2 client secret. If argument starts with file:// it reads the secret from a file.',env='CONFIG_OAUTH2_CLIENT_SECRET',xor:'oauth2-secret',required=''"                                                        yaml:"secret"`
	PrivateKey   Secret `json:"private-key"    kong:"help='oauth2 client private key. Secure alternative to oauth2.client.secret. If argument starts with file:// it reads the secret from a file.',env='CONFIG_OAUTH2_CLIENT_PRIVATE__KEY',xor:'oauth2-secret',required=''" yaml:"private-key"`
	PrivateKeyID string `json:"private-key-id" kong:"help='oauth2 client private key id. If specified, JWT assertions will be generated with the specific kid header.',env='CONFIG_OAUTH2_CLIENT_PRIVATE__KEY__ID'"                                                          yaml:"private-key-id"`
}

type OAuth2Endpoints struct {
	Discovery *url.URL `json:"discovery" kong:"help='The flag is used to set a custom OAuth2 discovery URL. This URL retrieves the provider\\'s configuration details.',env='CONFIG_OAUTH2_ENDPOINT_DISCOVERY'" yaml:"discovery"`
	Auth      *url.URL `json:"auth"      kong:"help='The flag is used to specify a custom OAuth2 authorization endpoint.',env='CONFIG_OAUTH2_ENDPOINT_AUTH',and:'oauth2-custom-url'"                            yaml:"auth"`
	Token     *url.URL `json:"token"     kong:"help='The flag is used to specify a custom OAuth2 token endpoint.',env='CONFIG_OAUTH2_ENDPOINT_TOKEN',and:'oauth2-custom-url'"                                   yaml:"token"`
}

type OAuth2Validate struct {
	CommonName              string   `json:"common-name"                kong:"help='validate common_name from OpenVPN with ID Token claim. For example: preferred_username or sub',env='CONFIG_OAUTH2_VALIDATE_COMMON__NAME'"                                                              yaml:"common-name"`
	CEL                     string   `json:"cel"                        kong:"help='CEL expression for custom token validation. The expression must evaluate to a boolean value. Example: openVPNUserCommonName == oauth2TokenClaims.preferred_username',env='CONFIG_OAUTH2_VALIDATE_CEL'" yaml:"cel"`
	Acr                     []string `json:"acr"                        kong:"help='oauth2 required acr values. Comma separated list. Example: phr,phrh',env='CONFIG_OAUTH2_VALIDATE_ACR'"                                                                                                 yaml:"acr"`
	Groups                  []string `json:"groups"                     kong:"help='oauth2 required user groups. If multiple groups are configured, the user needs to be least in one group. Comma separated list. Example: group1,group2,group3',env='CONFIG_OAUTH2_VALIDATE_GROUPS'"     yaml:"groups"`
	Roles                   []string `json:"roles"                      kong:"help='oauth2 required user roles. If multiple role are configured, the user needs to be least in one role. Comma separated list. Example: role1,role2,role3',env='CONFIG_OAUTH2_VALIDATE_ROLES'"             yaml:"roles"`
	IPAddr                  bool     `json:"ipaddr"                     kong:"help='validate client ipaddr between VPN and OIDC token',env='CONFIG_OAUTH2_VALIDATE_IPADDR'"                                                                                                                yaml:"ipaddr"`
	Issuer                  bool     `json:"issuer"                     kong:"help='validate issuer from OIDC discovery',env='CONFIG_OAUTH2_VALIDATE_ISSUER'"                                                                                                                              yaml:"issuer"`
	CommonNameCaseSensitive bool     `json:"common-name-case-sensitive" kong:"help='If true, openvpn-auth-oauth2 will validate the common case in sensitive mode',env='CONFIG_OAUTH2_VALIDATE_COMMON__NAME__CASE__SENSITIVE'"                                                              yaml:"common-name-case-sensitive"`
}

type OAuth2Refresh struct {
	Secret       Secret        `json:"secret"         kong:"help='Required, if oauth2.refresh.enabled=true. Random generated secret for token encryption. Must be 16, 24 or 32 characters. If argument starts with file:// it reads the secret from a file.',env='CONFIG_OAUTH2_REFRESH_SECRET'"      yaml:"secret"`
	Expires      time.Duration `json:"expires"        kong:"help='TTL of stored oauth2 token.',env='CONFIG_OAUTH2_REFRESH_EXPIRES'"                                                                                                                                                                   yaml:"expires"`
	Enabled      bool          `json:"enabled"        kong:"help='If true, openvpn-auth-oauth2 stores refresh tokens and will use it do an non-interaction reauth.',env='CONFIG_OAUTH2_REFRESH_ENABLED'"                                                                                              yaml:"enabled"`
	UseSessionID bool          `json:"use-session-id" kong:"help='If true, openvpn-auth-oauth2 will use the session_id to refresh sessions on initial auth. Requires \\'auth-token-gen [lifetime] external-auth\\' on OpenVPN server.',env='CONFIG_OAUTH2_REFRESH_USE__SESSION__ID'"                  yaml:"use-session-id"`
	ValidateUser bool          `json:"validate-user"  kong:"help='If true, openvpn-auth-oauth2 will validate the user against the OIDC provider on each refresh. Usefully, if API limits are exceeded or OIDC provider can\\'t deliver an refresh token.',env='CONFIG_OAUTH2_REFRESH_VALIDATE__USER'" yaml:"validate-user"`
}

type OpenVPNPassthrough struct {
	Address     *url.URL `json:"address"      kong:"help='The address of the pass-through socket. Must start with unix:// or tcp://',env='CONFIG_OPENVPN_PASS__THROUGH_ADDRESS'"                                                                               yaml:"address"`
	Password    Secret   `json:"password"     kong:"help='The password for the pass-through socket. If argument starts with file:// it reads the secret from a file.',env='CONFIG_OPENVPN_PASS__THROUGH_PASSWORD'"                                             yaml:"password"`
	SocketGroup string   `json:"socket-group" kong:"help='The group for the pass-through socket. Used only, if openvpn.pass-through.address starts with unix:// If empty, the group of the process is used.',env='CONFIG_OPENVPN_PASS__THROUGH_SOCKET__GROUP'" yaml:"socket-group"`
	SocketMode  uint     `json:"socket-mode"  kong:"help='The unix file permission mode for the pass-through socket. Used only, if openvpn.pass-through.address starts with unix://',env='CONFIG_OPENVPN_PASS__THROUGH_SOCKET__MODE'"                          yaml:"socket-mode"`
	Enabled     bool     `json:"enabled"      kong:"help='If true, openvpn-auth-oauth2 will setup a pass-through socket for the OpenVPN management interface.',env='CONFIG_OPENVPN_PASS__THROUGH_ENABLED'"                                                     yaml:"enabled"`
}

type Debug struct {
	Listen string `json:"listen" kong:"help='listen addr for debug/pprof endpoint',env='CONFIG_DEBUG_LISTEN'"                      yaml:"listen"`
	Pprof  bool   `json:"pprof"  kong:"help='enable go profiling endpoint (never expose this to public)',env='CONFIG_DEBUG_PPROF'" yaml:"pprof"`
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
