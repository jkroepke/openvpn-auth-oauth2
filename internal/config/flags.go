package config

import (
	"flag"
)

// flagSetDebug registers debug flags (deprecated: use registerFlags instead).
//
//goland:noinspection GoMixedReceiverTypes
func (c *Config) flagSetDebug(flagSet *flag.FlagSet) {
	c.registerBoolFlag(flagSet, &c.Debug.Pprof, "debug.pprof",
		"Enables go profiling endpoint. This should be never exposed.")
	c.registerStringFlag(flagSet, &c.Debug.Listen, "debug.listen",
		"listen address for go profiling endpoint")
}

// flagSetLog registers log flags (deprecated: use registerFlags instead).
//
//goland:noinspection GoMixedReceiverTypes
func (c *Config) flagSetLog(flagSet *flag.FlagSet) {
	c.registerBoolFlag(flagSet, &c.Log.VPNClientIP, "log.vpn-client-ip",
		"log IP of VPN client. Useful to have an identifier between OpenVPN and openvpn-auth-oauth2.")
	c.registerStringFlag(flagSet, &c.Log.Format, "log.format",
		"log format. json or console")
	c.registerTextFlag(flagSet, &c.Log.Level, "log.level",
		"log level. Can be one of: debug, info, warn, error")
}

// flagSetHTTP registers HTTP flags (deprecated: use registerFlags instead).
//
//goland:noinspection GoMixedReceiverTypes
func (c *Config) flagSetHTTP(flagSet *flag.FlagSet) {
	c.registerStringFlag(flagSet, &c.HTTP.Listen, "http.listen",
		"listen addr for client listener")
	c.registerBoolFlag(flagSet, &c.HTTP.TLS, "http.tls",
		"enable TLS listener")
	c.registerTextFlag(flagSet, &c.HTTP.BaseURL, "http.baseurl",
		"listen addr for client listener")
	c.registerTextFlag(flagSet, &c.HTTP.Secret, "http.secret",
		"Random generated secret for cookie encryption. Must be 16, 24 or 32 characters. "+
			"If argument starts with file:// it reads the secret from a file.")
	c.registerStringFlag(flagSet, &c.HTTP.KeyFile, "http.key",
		"Path to tls server key used for TLS listener.")
	c.registerStringFlag(flagSet, &c.HTTP.CertFile, "http.cert",
		"Path to tls server certificate used for TLS listener.")
	c.registerTextFlag(flagSet, &c.HTTP.Template, "http.template",
		"Path to a HTML file which is displayed at the end of the screen. "+
			"See https://github.com/jkroepke/openvpn-auth-oauth2/wiki/Layout-Customization for more information.")
	c.registerBoolFlag(flagSet, &c.HTTP.Check.IPAddr, "http.check.ipaddr",
		"Check if client IP in http and VPN is equal")
	c.registerBoolFlag(flagSet, &c.HTTP.EnableProxyHeaders, "http.enable-proxy-headers",
		"Use X-Forward-For http header for client ips")
	c.registerBoolFlag(flagSet, &c.HTTP.ShortURL, "http.short-url",
		"Enable short URL. The URL which is used for initial authentication will be reduced to /?s=... instead of /oauth2/start?state=...")
	c.registerTextFlag(flagSet, &c.HTTP.AssetPath, "http.assets-path",
		"Custom path to the assets directory. Files in this directory will be served under /assets/ and having an higher priority than the embedded assets.")
}

// flagSetOpenVPN registers OpenVPN flags (deprecated: use registerFlags instead).
//
//goland:noinspection GoMixedReceiverTypes
func (c *Config) flagSetOpenVPN(flagSet *flag.FlagSet) {
	c.registerTextFlag(flagSet, &c.OpenVPN.Addr, "openvpn.addr",
		"openvpn management interface addr. Must start with unix:// or tcp://")
	c.registerTextFlag(flagSet, &c.OpenVPN.Password, "openvpn.password",
		"openvpn management interface password. If argument starts with file:// it reads the secret from a file.")
	c.registerBoolFlag(flagSet, &c.OpenVPN.AuthTokenUser, "openvpn.auth-token-user",
		"Override the username of a session with the username from the token by using auth-token-user, if the client username is empty")
	c.registerDurationFlag(flagSet, &c.OpenVPN.AuthPendingTimeout, "openvpn.auth-pending-timeout",
		"How long OpenVPN server wait until user is authenticated")
	c.registerTextFlag(flagSet, &c.OpenVPN.Bypass.CommonNames, "openvpn.bypass.common-names",
		"Skip OAuth authentication for client certificate common names (CNs) matching any of the given regular expressions. "+
			"Multiple expressions can be provided as a comma-separated list. "+
			"Regular expressions are automatically anchored (^…$) by default, so \"client\" matches only \"client\". "+
			"To allow partial matches, specify explicitly (e.g. \"client.*\").")
	c.registerBoolFlag(flagSet, &c.OpenVPN.ClientConfig.Enabled, "openvpn.client-config.enabled",
		"If true, openvpn-auth-oauth2 will read the CCD directory for additional configuration. This function mimic the client-config-dir directive in OpenVPN.")
	c.registerTextFlag(flagSet, &c.OpenVPN.ClientConfig.Path, "openvpn.client-config.path",
		"Path to the CCD directory. openvpn-auth-oauth2 will look for an file with an .conf suffix and returns the content back.")
	c.registerStringFlag(flagSet, &c.OpenVPN.ClientConfig.TokenClaim, "openvpn.client-config.token-claim",
		"If non-empty, the value of the token claim is used to lookup the configuration file in the CCD directory. If empty, the common name is used.")
	c.registerBoolFlag(flagSet, &c.OpenVPN.ClientConfig.UserSelector.Enabled, "openvpn.client-config.user-selector.enabled",
		"If true, openvpn-auth-oauth2 will display a profile selection UI after OAuth2 authentication, allowing users to choose their client configuration profile. "+
			"Profile options are populated from openvpn.client-config.user-selector.static-values and openvpn.client-config.token-claim (if configured). "+
			"After selection, the chosen profile name is used to lookup the configuration file in the CCD directory.")
	c.registerTextFlag(flagSet, &c.OpenVPN.ClientConfig.UserSelector.StaticValues, "openvpn.client-config.user-selector.static-values",
		"Comma-separated list of static profile names that are always available in the profile selector UI. "+
			"These profiles will be displayed as selectable options for all users.")
	c.registerStringFlag(flagSet, &c.OpenVPN.CommonName.EnvironmentVariableName, "openvpn.common-name.environment-variable-name",
		"Name of the environment variable in the OpenVPN management interface which contains the common name. "+
			"If username-as-common-name is enabled, this should be set to 'username' to use the username as common name. "+
			"Other values like 'X509_0_emailAddress' are supported. "+
			"See https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/#environmental-variables for more information.")
	c.registerTextFlag(flagSet, &c.OpenVPN.CommonName.Mode, "openvpn.common-name.mode",
		"If common names are too long, use md5/sha1 to hash them or omit to skip them. "+
			"If omit, oauth2.validate.common-name does not work anymore. Values: [plain,omit]")
	c.registerBoolFlag(flagSet, &c.OpenVPN.OverrideUsername, "openvpn.override-username",
		"Requires OpenVPN Server 2.7! "+
			"If true, openvpn-auth-oauth2 use the override-username command to set the username in OpenVPN connection. "+
			"This is useful to use real usernames in OpenVPN statistics. The username will be set after client configs are read. "+
			"Read OpenVPN man page for limitations of the override-username.")
	c.registerBoolFlag(flagSet, &c.OpenVPN.Passthrough.Enabled, "openvpn.pass-through.enabled",
		"If true, openvpn-auth-oauth2 will setup a pass-through socket for the OpenVPN management interface.")
	c.registerTextFlag(flagSet, &c.OpenVPN.Passthrough.Address, "openvpn.pass-through.address",
		"The address of the pass-through socket. Must start with unix:// or tcp://")
	c.registerTextFlag(flagSet, &c.OpenVPN.Passthrough.Password, "openvpn.pass-through.password",
		"The password for the pass-through socket. If argument starts with file:// it reads the secret from a file.")
	c.registerStringFlag(flagSet, &c.OpenVPN.Passthrough.SocketGroup, "openvpn.pass-through.socket-group",
		"The group for the pass-through socket. Used only, if openvpn.pass-through.address starts with unix:// "+
			"If empty, the group of the process is used.")
	c.registerUintFlag(flagSet, &c.OpenVPN.Passthrough.SocketMode, "openvpn.pass-through.socket-mode",
		"The unix file permission mode for the pass-through socket. Used only, if openvpn.pass-through.address starts with unix://")
	c.registerBoolFlag(flagSet, &c.OpenVPN.ReAuthentication, "openvpn.reauthentication",
		"If set to false, openvpn-auth-oauth2 rejects all re-authentication requests.")
}

// flagSetOAuth2 registers OAuth2 flags (deprecated: use registerFlags instead).
//
//goland:noinspection GoMixedReceiverTypes
func (c *Config) flagSetOAuth2(flagSet *flag.FlagSet) {
	c.registerTextFlag(flagSet, &c.OAuth2.Issuer, "oauth2.issuer",
		"oauth2 issuer")
	c.registerStringFlag(flagSet, &c.OAuth2.Provider, "oauth2.provider",
		"oauth2 provider")
	c.registerStringFlag(flagSet, &c.OAuth2.AuthorizeParams, "oauth2.authorize-params",
		"additional url query parameter to authorize endpoint")
	c.registerTextFlag(flagSet, &c.OAuth2.Endpoints.Discovery, "oauth2.endpoint.discovery",
		"The flag is used to set a custom OAuth2 discovery URL. This URL retrieves the provider's configuration details.")
	c.registerTextFlag(flagSet, &c.OAuth2.Endpoints.Auth, "oauth2.endpoint.auth",
		"The flag is used to specify a custom OAuth2 authorization endpoint.")
	c.registerTextFlag(flagSet, &c.OAuth2.Endpoints.Token, "oauth2.endpoint.token",
		"The flag is used to specify a custom OAuth2 token endpoint.")
	c.registerStringFlag(flagSet, &c.OAuth2.Client.ID, "oauth2.client.id",
		"oauth2 client id")
	c.registerTextFlag(flagSet, &c.OAuth2.Client.PrivateKey, "oauth2.client.private-key",
		"oauth2 client private key. Secure alternative to oauth2.client.secret. If argument starts with file:// it reads the secret from a file.")
	c.registerStringFlag(flagSet, &c.OAuth2.Client.PrivateKeyID, "oauth2.client.private-key-id",
		"oauth2 client private key id. If specified, JWT assertions will be generated with the specific kid header.")
	c.registerTextFlag(flagSet, &c.OAuth2.Client.Secret, "oauth2.client.secret",
		"oauth2 client secret. If argument starts with file:// it reads the secret from a file.")
	c.registerBoolFlag(flagSet, &c.OAuth2.PKCE, "oauth2.pkce",
		"If true, Proof Key for Code Exchange (PKCE) RFC 7636 is used for token exchange.")
	c.registerBoolFlag(flagSet, &c.OAuth2.UserInfo, "oauth2.user-info",
		"If true, openvpn-auth-oauth2 uses the OIDC UserInfo endpoint to fetch additional information about the user (e.g. groups).")
	c.registerStringFlag(flagSet, &c.OAuth2.GroupsClaim, "oauth2.groups-claim",
		"Defines the claim name in the ID Token which contains the user groups.")
	c.registerBoolFlag(flagSet, &c.OAuth2.Nonce, "oauth2.nonce",
		"If true, a nonce will be defined on the auth URL which is expected inside the token.")
	c.registerTextFlag(flagSet, &c.OAuth2.RefreshNonce, "oauth2.refresh-nonce",
		"Controls nonce behavior on refresh token requests. "+
			"Options: auto (try with nonce, retry without on error), "+
			"empty (always use empty nonce), "+
			"equal (use same nonce as initial auth).")
	c.registerTextFlag(flagSet, &c.OAuth2.AuthStyle, "oauth2.auth-style",
		"Auth style represents how requests for tokens are authenticated to the server. "+
			"Possible values: AuthStyleAutoDetect, AuthStyleInParams, AuthStyleInHeader. "+
			"See https://pkg.go.dev/golang.org/x/oauth2#AuthStyle")
	c.registerBoolFlag(flagSet, &c.OAuth2.Refresh.Enabled, "oauth2.refresh.enabled",
		"If true, openvpn-auth-oauth2 stores refresh tokens and will use it do an non-interaction reauth.")
	c.registerDurationFlag(flagSet, &c.OAuth2.Refresh.Expires, "oauth2.refresh.expires",
		"TTL of stored oauth2 token.")
	c.registerTextFlag(flagSet, &c.OAuth2.Refresh.Secret, "oauth2.refresh.secret",
		"Required, if oauth2.refresh.enabled=true. Random generated secret for token encryption. "+
			"Must be 16, 24 or 32 characters. If argument starts with file:// it reads the secret from a file.")
	c.registerBoolFlag(flagSet, &c.OAuth2.Refresh.UseSessionID, "oauth2.refresh.use-session-id",
		"If true, openvpn-auth-oauth2 will use the session_id to refresh sessions on initial auth. "+
			"Requires 'auth-token-gen [lifetime] external-auth' on OpenVPN server.")
	c.registerBoolFlag(flagSet, &c.OAuth2.Refresh.ValidateUser, "oauth2.refresh.validate-user",
		"If true, openvpn-auth-oauth2 will validate the user against the OIDC provider on each refresh. "+
			"Usefully, if API limits are exceeded or OIDC provider can't deliver an refresh token.")
	c.registerTextFlag(flagSet, &c.OAuth2.Validate.Acr, "oauth2.validate.acr",
		"oauth2 required acr values. Comma separated list. "+
			"Example: phr,phrh")
	c.registerTextFlag(flagSet, &c.OAuth2.Validate.Groups, "oauth2.validate.groups",
		"oauth2 required user groups. If multiple groups are configured, the user needs to be least in one group. "+
			"Comma separated list. Example: group1,group2,group3")
	c.registerTextFlag(flagSet, &c.OAuth2.Validate.Roles, "oauth2.validate.roles",
		"oauth2 required user roles. If multiple role are configured, the user needs to be least in one role. "+
			"Comma separated list. Example: role1,role2,role3")
	c.registerBoolFlag(flagSet, &c.OAuth2.Validate.IPAddr, "oauth2.validate.ipaddr",
		"validate client ipaddr between VPN and OIDC token")
	c.registerBoolFlag(flagSet, &c.OAuth2.Validate.Issuer, "oauth2.validate.issuer",
		"validate issuer from OIDC discovery")
	c.registerStringFlag(flagSet, &c.OAuth2.Validate.CommonName, "oauth2.validate.common-name",
		"validate common_name from OpenVPN with ID Token claim. For example: preferred_username or sub")
	c.registerBoolFlag(flagSet, &c.OAuth2.Validate.CommonNameCaseSensitive, "oauth2.validate.common-name-case-sensitive",
		"If true, openvpn-auth-oauth2 will validate the common case in sensitive mode")
	c.registerStringFlag(flagSet, &c.OAuth2.Validate.CEL, "oauth2.validate.cel",
		"CEL expression for custom token validation. "+
			"The expression must evaluate to a boolean value. "+
			"Example: openVPNUserCommonName == oauth2TokenClaims.preferred_username")
	c.registerTextFlag(flagSet, &c.OAuth2.Scopes, "oauth2.scopes",
		"oauth2 token scopes. Defaults depends on oauth2.provider. Comma separated list. "+
			"Example: openid,profile,email")
	c.registerStringFlag(flagSet, &c.OAuth2.OpenVPNUsernameClaim, "oauth2.openvpn-username-claim",
		"The claim name in the ID Token which should be used as username in OpenVPN. If empty, the common name is used.")
	c.registerStringFlag(flagSet, &c.OAuth2.OpenVPNUsernameCEL, "oauth2.openvpn-username-cel",
		"CEL expression to extract the username from the token. The expression must evaluate to a string value. "+
			"Example: oauth2TokenClaims.sub "+
			"Note: oauth2.openvpn-username-claim and oauth2.openvpn-username-cel cannot be set at the same time.")
}
