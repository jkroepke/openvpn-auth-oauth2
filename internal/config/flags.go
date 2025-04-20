package config

import (
	"flag"
)

//goland:noinspection GoMixedReceiverTypes
func (c *Config) flagSetDebug(flagSet *flag.FlagSet) {
	flagSet.BoolVar(
		&c.Debug.Pprof,
		"debug.pprof",
		lookupEnvOrDefault("debug.pprof", Defaults.Debug.Pprof),
		"Enables go profiling endpoint. This should be never exposed.",
	)
	flagSet.StringVar(
		&c.Debug.Listen,
		"debug.listen",
		lookupEnvOrDefault("debug.listen", Defaults.Debug.Listen),
		"listen address for go profiling endpoint",
	)
}

//goland:noinspection GoMixedReceiverTypes
func (c *Config) flagSetLog(flagSet *flag.FlagSet) {
	flagSet.BoolVar(
		&c.Log.VPNClientIP,
		"log.vpn-client-ip",
		lookupEnvOrDefault("log.vpn-client-ip", Defaults.Log.VPNClientIP),
		"log IP of VPN client. Useful to have an identifier between OpenVPN and openvpn-auth-oauth2.",
	)
	flagSet.StringVar(
		&c.Log.Format,
		"log.format",
		lookupEnvOrDefault("log.format", Defaults.Log.Format),
		"log format. json or console",
	)
	flagSet.TextVar(
		&c.Log.Level,
		"log.level",
		lookupEnvOrDefault("log.level", Defaults.Log.Level),
		"log level. Can be one of: debug, info, warn, error",
	)
}

//goland:noinspection GoMixedReceiverTypes
func (c *Config) flagSetHTTP(flagSet *flag.FlagSet) {
	flagSet.StringVar(
		&c.HTTP.Listen,
		"http.listen",
		lookupEnvOrDefault("http.listen", Defaults.HTTP.Listen),
		"listen addr for client listener",
	)
	flagSet.BoolVar(
		&c.HTTP.TLS,
		"http.tls",
		lookupEnvOrDefault("http.tls", Defaults.HTTP.TLS),
		"enable TLS listener",
	)
	flagSet.TextVar(
		c.HTTP.BaseURL,
		"http.baseurl",
		lookupEnvOrDefault("http.baseurl", Defaults.HTTP.BaseURL),
		"listen addr for client listener",
	)
	flagSet.TextVar(
		&c.HTTP.Secret,
		"http.secret",
		lookupEnvOrDefault("http.secret", Defaults.HTTP.Secret),
		"Random generated secret for cookie encryption. Must be 16, 24 or 32 characters. "+
			"If argument starts with file:// it reads the secret from a file.",
	)
	flagSet.StringVar(
		&c.HTTP.KeyFile,
		"http.key",
		lookupEnvOrDefault("http.key", Defaults.HTTP.KeyFile),
		"Path to tls server key used for TLS listener.",
	)
	flagSet.StringVar(
		&c.HTTP.CertFile,
		"http.cert",
		lookupEnvOrDefault("http.key", Defaults.HTTP.CertFile),
		"Path to tls server certificate used for TLS listener.",
	)
	flagSet.TextVar(
		&c.HTTP.Template,
		"http.template",
		lookupEnvOrDefault("http.template", Defaults.HTTP.Template),
		"Path to a HTML file which is displayed at the end of the screen. "+
			"See https://github.com/jkroepke/openvpn-auth-oauth2/wiki/Layout-Customization for more information.",
	)
	flagSet.BoolVar(
		&c.HTTP.Check.IPAddr,
		"http.check.ipaddr",
		lookupEnvOrDefault("http.check.ipaddr", Defaults.HTTP.Check.IPAddr),
		"Check if client IP in http and VPN is equal",
	)
	flagSet.BoolVar(
		&c.HTTP.EnableProxyHeaders,
		"http.enable-proxy-headers",
		lookupEnvOrDefault("http.enable-proxy-headers", Defaults.HTTP.EnableProxyHeaders),
		"Use X-Forward-For http header for client ips",
	)
	flagSet.TextVar(
		&c.HTTP.AssetPath,
		"http.assets-path",
		lookupEnvOrDefault("http.assets-path", Defaults.HTTP.AssetPath),
		"Custom path to the assets directory. Files in this directory will be served under /assets/ and having an higher priority than the embedded assets.",
	)
}

//goland:noinspection GoMixedReceiverTypes
func (c *Config) flagSetOpenVPN(flagSet *flag.FlagSet) {
	flagSet.TextVar(
		c.OpenVpn.Addr,
		"openvpn.addr",
		lookupEnvOrDefault("openvpn.addr", Defaults.OpenVpn.Addr),
		"openvpn management interface addr. Must start with unix:// or tcp://",
	)
	flagSet.TextVar(
		&c.OpenVpn.Password,
		"openvpn.password",
		lookupEnvOrDefault("openvpn.password", Defaults.OpenVpn.Password),
		"openvpn management interface password. If argument starts with file:// it reads the secret from a file.",
	)
	flagSet.BoolVar(
		&c.OpenVpn.AuthTokenUser,
		"openvpn.auth-token-user",
		lookupEnvOrDefault("openvpn.auth-token-user", Defaults.OpenVpn.AuthTokenUser),
		"Override the username of a session with the username from the token by using auth-token-user, if the client username is empty",
	)
	flagSet.DurationVar(
		&c.OpenVpn.AuthPendingTimeout,
		"openvpn.auth-pending-timeout",
		lookupEnvOrDefault("openvpn.auth-pending-timeout", Defaults.OpenVpn.AuthPendingTimeout),
		"How long OpenVPN server wait until user is authenticated",
	)
	flagSet.TextVar(
		&c.OpenVpn.Bypass.CommonNames,
		"openvpn.bypass.common-names",
		lookupEnvOrDefault("openvpn.bypass.common-names", Defaults.OpenVpn.Bypass.CommonNames),
		"bypass oauth authentication for CNs. Comma separated list.",
	)
	flagSet.StringVar(
		&c.OpenVpn.CommonName.EnvironmentVariableName,
		"openvpn.common-name.environment-variable-name",
		lookupEnvOrDefault("openvpn.common-name.environment-variable-name", Defaults.OpenVpn.CommonName.EnvironmentVariableName),
		"Name of the environment variable in the OpenVPN management interface which contains the common name. "+
			"If username-as-common-name is enabled, this should be set to 'username' to use the username as common name. "+
			"Other values like 'X509_0_emailAddress' are supported. "+
			"See https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/#environmental-variables for more information.",
	)
	flagSet.TextVar(
		&c.OpenVpn.CommonName.Mode,
		"openvpn.common-name.mode",
		lookupEnvOrDefault("openvpn.common-name.mode", Defaults.OpenVpn.CommonName.Mode),
		"If common names are too long, use md5/sha1 to hash them or omit to skip them. "+
			"If omit, oauth2.validate.common-name does not work anymore. Values: [plain,omit]",
	)
	flagSet.BoolVar(
		&c.OpenVpn.OverrideUsername,
		"openvpn.override-username",
		lookupEnvOrDefault("openvpn.override-username", Defaults.OpenVpn.OverrideUsername),
		"Requires OpenVPN Server 2.7! "+
			"If true, openvpn-auth-oauth2 use the override-username command to set the username in OpenVPN connection. "+
			"This is useful to use real usernames in OpenVPN statistics. The username will be set after client configs are read. "+
			"Read openvpn man page for limitations of the override-username.",
	)
	flagSet.BoolVar(
		&c.OpenVpn.Passthrough.Enabled,
		"openvpn.pass-through.enabled",
		lookupEnvOrDefault("openvpn.pass-through.enabled", Defaults.OpenVpn.Passthrough.Enabled),
		"If true, openvpn-auth-oauth2 will setup a pass-through socket for the OpenVPN management interface.",
	)
	flagSet.TextVar(
		c.OpenVpn.Passthrough.Address,
		"openvpn.pass-through.address",
		lookupEnvOrDefault("openvpn.pass-through.address", Defaults.OpenVpn.Passthrough.Address),
		"The address of the pass-through socket. Must start with unix:// or tcp://",
	)
	flagSet.TextVar(
		&c.OpenVpn.Passthrough.Password,
		"openvpn.pass-through.password",
		lookupEnvOrDefault("openvpn.pass-through.password", Defaults.OpenVpn.Passthrough.Password),
		"The password for the pass-through socket. If argument starts with file:// it reads the secret from a file.",
	)
	flagSet.StringVar(
		&c.OpenVpn.Passthrough.SocketGroup,
		"openvpn.pass-through.socket-group",
		lookupEnvOrDefault("openvpn.pass-through.socket-group", Defaults.OpenVpn.Passthrough.SocketGroup),
		"The group for the pass-through socket. Used only, if openvpn.pass-through.address starts with unix:// "+
			"If empty, the group of the process is used.",
	)
	flagSet.UintVar(
		&c.OpenVpn.Passthrough.SocketMode,
		"openvpn.pass-through.socket-mode",
		lookupEnvOrDefault("openvpn.pass-through.socket-mode", Defaults.OpenVpn.Passthrough.SocketMode),
		"The unix file permission mode for the pass-through socket. Used only, if openvpn.pass-through.address starts with unix://",
	)
}

//goland:noinspection GoMixedReceiverTypes
func (c *Config) flagSetOAuth2(flagSet *flag.FlagSet) {
	flagSet.TextVar(
		c.OAuth2.Issuer,
		"oauth2.issuer",
		lookupEnvOrDefault("oauth2.issuer", Defaults.OAuth2.Issuer),
		"oauth2 issuer",
	)
	flagSet.StringVar(
		&c.OAuth2.Provider,
		"oauth2.provider",
		lookupEnvOrDefault("oauth2.provider", Defaults.OAuth2.Provider),
		"oauth2 provider",
	)
	flagSet.StringVar(
		&c.OAuth2.AuthorizeParams,
		"oauth2.authorize-params",
		lookupEnvOrDefault("oauth2.authorize-params", Defaults.OAuth2.AuthorizeParams),
		"additional url query parameter to authorize endpoint",
	)
	flagSet.TextVar(
		c.OAuth2.Endpoints.Discovery,
		"oauth2.endpoint.discovery",
		lookupEnvOrDefault("oauth2.endpoint.discovery", Defaults.OAuth2.Endpoints.Discovery),
		"The flag is used to set a custom OAuth2 discovery URL. This URL retrieves the provider's configuration details.",
	)
	flagSet.TextVar(
		c.OAuth2.Endpoints.Auth,
		"oauth2.endpoint.auth",
		lookupEnvOrDefault("oauth2.endpoint.auth", Defaults.OAuth2.Endpoints.Auth),
		"The flag is used to specify a custom OAuth2 authorization endpoint.",
	)
	flagSet.TextVar(
		c.OAuth2.Endpoints.Token,
		"oauth2.endpoint.token",
		lookupEnvOrDefault("oauth2.endpoint.token", Defaults.OAuth2.Endpoints.Token),
		"The flag is used to specify a custom OAuth2 token endpoint.",
	)
	flagSet.StringVar(
		&c.OAuth2.Client.ID,
		"oauth2.client.id",
		lookupEnvOrDefault("oauth2.client.id", Defaults.OAuth2.Client.ID),
		"oauth2 client id",
	)
	flagSet.TextVar(
		&c.OAuth2.Client.PrivateKey,
		"oauth2.client.private-key",
		lookupEnvOrDefault("oauth2.client.private-key", Defaults.OAuth2.Client.PrivateKey),
		"oauth2 client private key. Secure alternative to oauth2.client.secret. If argument starts with file:// it reads the secret from a file.",
	)
	flagSet.StringVar(
		&c.OAuth2.Client.PrivateKeyID,
		"oauth2.client.private-key-id",
		lookupEnvOrDefault("oauth2.client.private-key-id", Defaults.OAuth2.Client.PrivateKeyID),
		"oauth2 client private key id. If specified, JWT assertions will be generated with the specific kid header.",
	)
	flagSet.TextVar(
		&c.OAuth2.Client.Secret,
		"oauth2.client.secret",
		lookupEnvOrDefault("oauth2.client.secret", Defaults.OAuth2.Client.Secret),
		"oauth2 client secret. If argument starts with file:// it reads the secret from a file.",
	)
	flagSet.BoolVar(
		&c.OAuth2.PKCE,
		"oauth2.pkce",
		lookupEnvOrDefault("oauth2.pkce", Defaults.OAuth2.PKCE),
		"If true, Proof Key for Code Exchange (PKCE) RFC 7636 is used for token exchange.",
	)
	flagSet.BoolVar(
		&c.OAuth2.Nonce,
		"oauth2.nonce",
		lookupEnvOrDefault("oauth2.nonce", Defaults.OAuth2.Nonce),
		"If true, a nonce will be defined on the auth URL which is expected inside the token.",
	)
	flagSet.TextVar(
		&c.OAuth2.AuthStyle,
		"oauth2.auth-style",
		lookupEnvOrDefault("oauth2.auth-style", Defaults.OAuth2.AuthStyle),
		"Auth style represents how requests for tokens are authenticated to the server. "+
			"Possible values: AuthStyleAutoDetect, AuthStyleInParams, AuthStyleInHeader. "+
			"See https://pkg.go.dev/golang.org/x/oauth2#AuthStyle",
	)
	flagSet.BoolVar(
		&c.OAuth2.Refresh.Enabled,
		"oauth2.refresh.enabled",
		lookupEnvOrDefault("oauth2.refresh.enabled", Defaults.OAuth2.Refresh.Enabled),
		"If true, openvpn-auth-oauth2 stores refresh tokens and will use it do an non-interaction reauth.",
	)
	flagSet.DurationVar(
		&c.OAuth2.Refresh.Expires,
		"oauth2.refresh.expires",
		lookupEnvOrDefault("oauth2.refresh.expires", Defaults.OAuth2.Refresh.Expires),
		"TTL of stored oauth2 token.",
	)
	flagSet.TextVar(
		&c.OAuth2.Refresh.Secret,
		"oauth2.refresh.secret",
		lookupEnvOrDefault("oauth2.refresh.secret", Defaults.OAuth2.Refresh.Secret),
		"Required, if oauth2.refresh.enabled=true. Random generated secret for token encryption. "+
			"Must be 16, 24 or 32 characters. If argument starts with file:// it reads the secret from a file.",
	)
	flagSet.BoolVar(
		&c.OAuth2.Refresh.UseSessionID,
		"oauth2.refresh.use-session-id",
		lookupEnvOrDefault("oauth2.refresh.use-session-id", Defaults.OAuth2.Refresh.UseSessionID),
		"If true, openvpn-auth-oauth2 will use the session_id to refresh sessions on initial auth. "+
			"Requires 'auth-token-gen [lifetime] external-auth' on OpenVPN server.",
	)
	flagSet.BoolVar(
		&c.OAuth2.Refresh.ValidateUser,
		"oauth2.refresh.validate-user",
		lookupEnvOrDefault("oauth2.refresh.validate-user", Defaults.OAuth2.Refresh.ValidateUser),
		"If true, openvpn-auth-oauth2 will validate the user against the OIDC provider on each refresh. "+
			"Usefully, if API limits are exceeded or OIDC provider can't deliver an refresh token.",
	)
	flagSet.TextVar(
		&c.OAuth2.Validate.Acr,
		"oauth2.validate.acr",
		lookupEnvOrDefault("oauth2.validate.acr", Defaults.OAuth2.Validate.Acr),
		"oauth2 required acr values. Comma separated list. "+
			"Example: phr,phrh",
	)
	flagSet.TextVar(
		&c.OAuth2.Validate.Groups,
		"oauth2.validate.groups",
		lookupEnvOrDefault("oauth2.validate.groups", Defaults.OAuth2.Validate.Groups),
		"oauth2 required user groups. If multiple groups are configured, the user needs to be least in one group. "+
			"Comma separated list. Example: group1,group2,group3",
	)
	flagSet.TextVar(
		&c.OAuth2.Validate.Roles,
		"oauth2.validate.roles",
		lookupEnvOrDefault("oauth2.validate.roles", Defaults.OAuth2.Validate.Roles),
		"oauth2 required user roles. If multiple role are configured, the user needs to be least in one role. "+
			"Comma separated list. Example: role1,role2,role3",
	)
	flagSet.BoolVar(
		&c.OAuth2.Validate.IPAddr,
		"oauth2.validate.ipaddr",
		lookupEnvOrDefault("oauth2.validate.ipaddr", Defaults.OAuth2.Validate.IPAddr),
		"validate client ipaddr between VPN and oidc token",
	)
	flagSet.BoolVar(
		&c.OAuth2.Validate.Issuer,
		"oauth2.validate.issuer",
		lookupEnvOrDefault("oauth2.validate.issuer", Defaults.OAuth2.Validate.Issuer),
		"validate issuer from oidc discovery",
	)
	flagSet.StringVar(
		&c.OAuth2.Validate.CommonName,
		"oauth2.validate.common-name",
		lookupEnvOrDefault("oauth2.validate.common-name", Defaults.OAuth2.Validate.CommonName),
		"validate common_name from OpenVPN with IDToken claim. For example: preferred_username or sub",
	)
	flagSet.BoolVar(
		&c.OAuth2.Validate.CommonNameCaseSensitive,
		"oauth2.validate.common-name-case-sensitive",
		lookupEnvOrDefault("oauth2.validate.common-name-case-sensitive", Defaults.OAuth2.Validate.CommonNameCaseSensitive),
		"If true, openvpn-auth-oauth2 will validate the common case in sensitive mode",
	)
	flagSet.TextVar(
		&c.OAuth2.Scopes,
		"oauth2.scopes",
		lookupEnvOrDefault("oauth2.scopes", Defaults.OAuth2.Scopes),
		"oauth2 token scopes. Defaults depends on oauth2.provider. Comma separated list. "+
			"Example: openid,profile,email",
	)
}
