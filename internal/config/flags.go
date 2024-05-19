package config

import (
	"flag"
	"fmt"
	"log/slog"
	"strings"
)

const (
	Plugin = iota
	ManagementClient
)

// FlagSet configure the command line parser using the [flag] library.
func FlagSet(name string) *flag.FlagSet {
	flagSet := flag.NewFlagSet(name, flag.ContinueOnError)
	flagSet.Usage = func() {
		_, _ = fmt.Fprintf(flagSet.Output(), "Usage of %s:\r\n\r\n", name)
		// --help should display options with double dash
		flagSet.VisitAll(func(flag *flag.Flag) {
			flag.Name = "-" + flag.Name
		})
		flagSet.PrintDefaults()
	}

	flagSet.String(
		"config",
		"",
		"path to one .yaml config file",
	)
	flagSet.Bool(
		"version",
		false,
		"show version",
	)

	flagSetDebug(flagSet)
	flagSetLog(flagSet)
	flagSetHTTP(flagSet)
	flagSetOpenVPN(flagSet)
	flagSetOAuth2(flagSet)

	flagSet.VisitAll(func(flag *flag.Flag) {
		if flag.Name == "version" {
			return
		}

		env := strings.ToUpper(flag.Name)
		env = strings.ReplaceAll(env, ".", "_")
		env = strings.ReplaceAll(env, "-", "__")

		flag.Usage += fmt.Sprintf(" (env: %s%s)", envPrefix, env)
	})

	return flagSet
}

func flagSetDebug(flagSet *flag.FlagSet) {
	flagSet.Bool(
		"debug.pprof",
		Defaults.Debug.Pprof,
		"Enables go profiling endpoint. This should be never exposed.",
	)
	flagSet.String(
		"debug.listen",
		Defaults.Debug.Listen,
		"listen address for go profiling endpoint",
	)
}

func flagSetLog(flagSet *flag.FlagSet) {
	flagSet.Bool(
		"log.vpn-client-ip",
		Defaults.Log.VPNClientIP,
		"log IP of VPN client. Useful to have an identifier between OpenVPN and openvpn-auth-oauth2.",
	)
	flagSet.String(
		"log.format",
		Defaults.Log.Format,
		"log format. json or console",
	)
	flagSet.TextVar(new(slog.Level),
		"log.level",
		Defaults.Log.Level,
		"log level",
	)
}

func flagSetHTTP(flagSet *flag.FlagSet) {
	flagSet.String(
		"http.listen",
		Defaults.HTTP.Listen,
		"listen addr for client listener",
	)
	flagSet.Bool(
		"http.tls",
		Defaults.HTTP.TLS,
		"enable TLS listener",
	)
	flagSet.String(
		"http.baseurl",
		Defaults.HTTP.BaseURL.String(),
		"listen addr for client listener",
	)
	flagSet.TextVar(new(Secret),
		"http.secret",
		Defaults.HTTP.Secret,
		"Random generated secret for cookie encryption. Must be 16, 24 or 32 characters. "+
			"If argument starts with file:// it reads the secret from a file.",
	)
	flagSet.String(
		"http.key",
		Defaults.HTTP.KeyFile,
		"Path to tls server key",
	)
	flagSet.String(
		"http.cert",
		Defaults.HTTP.CertFile,
		"Path to tls server certificate",
	)
	flagSet.String(
		"http.template",
		"",
		"Path to a HTML file which is displayed at the end of the screen",
	)
	flagSet.Bool(
		"http.check.ipaddr",
		Defaults.HTTP.Check.IPAddr,
		"Check if client IP in http and VPN is equal",
	)
	flagSet.Bool(
		"http.enable-proxy-headers",
		Defaults.HTTP.EnableProxyHeaders,
		"Use X-Forward-For http header for client ips",
	)
	flagSet.String(
		"http.assets-path",
		Defaults.HTTP.AssetPath,
		"Custom path to the assets directory. Files in this directory will be served under /assets/ and having an higher priority than the embedded assets.",
	)
}

func flagSetOpenVPN(flagSet *flag.FlagSet) {
	flagSet.String(
		"openvpn.addr",
		Defaults.OpenVpn.Addr.String(),
		"openvpn management interface addr. Must start with unix:// or tcp://",
	)
	flagSet.TextVar(new(Secret),
		"openvpn.password",
		Defaults.OpenVpn.Password,
		"openvpn management interface password. If argument starts with file:// it reads the secret from a file.",
	)
	flagSet.Bool(
		"openvpn.auth-token-user",
		Defaults.OpenVpn.AuthTokenUser,
		"Override the username of a session with the username from the token by using auth-token-user, if the client username is empty",
	)
	flagSet.Duration(
		"openvpn.auth-pending-timeout",
		Defaults.OpenVpn.AuthPendingTimeout,
		"How long OpenVPN server wait until user is authenticated",
	)
	flagSet.TextVar(new(StringSlice),
		"openvpn.bypass.common-names",
		Defaults.OpenVpn.Bypass.CommonNames,
		"bypass oauth authentication for CNs. Comma separated list.",
	)
	flagSet.String(
		"openvpn.common-name.environment-variable",
		Defaults.OpenVpn.CommonName.EnvironmentVariableName,
		"Name of the environment variable in the OpenVPN management interface which contains the common name. "+
			"If username-as-common-name is enabled, this should be set to 'username' to use the username as common name. "+
			"Other values like 'X509_0_emailAddress' are supported. "+
			"See https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/#environmental-variables for more information.",
	)
	flagSet.TextVar(new(OpenVPNCommonNameMode),
		"openvpn.common-name.mode",
		Defaults.OpenVpn.CommonName.Mode,
		"If common names are too long, use md5/sha1 to hash them or omit to skip them. "+
			"If omit, oauth2.validate.common-name does not work anymore. Values: [plain,omit]",
	)
	flagSet.Bool(
		"openvpn.pass-through.enabled",
		Defaults.OpenVpn.Passthrough.Enabled,
		"If true, openvpn-auth-oauth2 will setup a pass-through socket for the OpenVPN management interface. ",
	)
	flagSet.String(
		"openvpn.pass-through.address",
		Defaults.OpenVpn.Passthrough.Address.String(),
		"The address of the pass-through socket. Must start with unix:// or tcp://",
	)
	flagSet.TextVar(new(Secret),
		"openvpn.pass-through.password",
		Defaults.OpenVpn.Passthrough.Password,
		"The password for the pass-through socket. If argument starts with file:// it reads the secret from a file.",
	)
	flagSet.String(
		"openvpn.pass-through.socket-group",
		Defaults.OpenVpn.Passthrough.SocketGroup,
		"The group for the pass-through socket. Used only, if openvpn.pass-through.address starts with unix:// "+
			"If empty, the group of the process is used.",
	)
	flagSet.Uint(
		"openvpn.pass-through.socket-mode",
		Defaults.OpenVpn.Passthrough.SocketMode,
		"The unix file permission mode for the pass-through socket. Used only, if openvpn.pass-through.address starts with unix://",
	)
}

func flagSetOAuth2(flagSet *flag.FlagSet) {
	flagSet.String(
		"oauth2.issuer",
		Defaults.OAuth2.Issuer.String(),
		"oauth2 issuer",
	)
	flagSet.String(
		"oauth2.provider",
		Defaults.OAuth2.Provider,
		"oauth2 provider",
	)
	flagSet.String(
		"oauth2.authorize-params",
		"",
		"additional url query parameter to authorize endpoint",
	)
	flagSet.String(
		"oauth2.endpoint.discovery",
		Defaults.OAuth2.Endpoints.Discovery.String(),
		"The flag is used to set a custom OAuth2 discovery URL. This URL retrieves the provider's configuration details.",
	)
	flagSet.String(
		"oauth2.endpoint.auth",
		Defaults.OAuth2.Endpoints.Auth.String(),
		"The flag is used to specify a custom OAuth2 authorization endpoint.",
	)
	flagSet.String(
		"oauth2.endpoint.token",
		Defaults.OAuth2.Endpoints.Token.String(),
		"The flag is used to specify a custom OAuth2 token endpoint.",
	)
	flagSet.String(
		"oauth2.client.id",
		Defaults.OAuth2.Client.ID,
		"oauth2 client id",
	)
	flagSet.TextVar(new(Secret),
		"oauth2.client.secret",
		Defaults.OAuth2.Client.Secret,
		"oauth2 client secret. If argument starts with file:// it reads the secret from a file.",
	)
	flagSet.Bool(
		"oauth2.pkce",
		Defaults.OAuth2.PKCE,
		"If true, Proof Key for Code Exchange (PKCE) RFC 7636 is used for token exchange.",
	)
	flagSet.Bool(
		"oauth2.nonce",
		Defaults.OAuth2.Nonce,
		"If true, a nonce will be defined on the auth URL which is expected inside the token.",
	)
	flagSet.TextVar(new(OAuth2AuthStyle),
		"oauth2.auth-style",
		Defaults.OAuth2.AuthStyle,
		"Auth style represents how requests for tokens are authenticated to the server. "+
			"Possible values: AuthStyleAutoDetect, AuthStyleInParams, AuthStyleInHeader. "+
			"See https://pkg.go.dev/golang.org/x/oauth2#AuthStyle",
	)
	flagSet.Bool(
		"oauth2.refresh.enabled",
		Defaults.OAuth2.Refresh.Enabled,
		"If true, openvpn-auth-oauth2 stores refresh tokens and will use it do an non-interaction reauth.",
	)
	flagSet.Duration(
		"oauth2.refresh.expires",
		Defaults.OAuth2.Refresh.Expires,
		"TTL of stored oauth2 token.",
	)
	flagSet.TextVar(new(Secret),
		"oauth2.refresh.secret",
		Defaults.OAuth2.Refresh.Secret,
		"Required, if oauth2.refresh.enabled=true. Random generated secret for token encryption. "+
			"Must be 16, 24 or 32 characters. If argument starts with file:// it reads the secret from a file.",
	)
	flagSet.Bool(
		"oauth2.refresh.use-session-id",
		Defaults.OAuth2.Refresh.UseSessionID,
		"If true, openvpn-auth-oauth2 will use the session_id to refresh sessions on initial auth. "+
			"Requires 'auth-token-gen [lifetime] external-auth' on OpenVPN server.",
	)
	flagSet.Bool(
		"oauth2.refresh.validate-user",
		Defaults.OAuth2.Refresh.ValidateUser,
		"If true, openvpn-auth-oauth2 will validate the user against the OIDC provider on each refresh. "+
			"Usefully, if API limits are exceeded or OIDC provider can't deliver an refresh token.",
	)
	flagSet.TextVar(new(StringSlice),
		"oauth2.validate.acr",
		Defaults.OAuth2.Validate.Acr,
		"oauth2 required acr values. Comma separated list. "+
			"Example: phr,phrh",
	)
	flagSet.TextVar(new(StringSlice),
		"oauth2.validate.groups",
		Defaults.OAuth2.Validate.Groups,
		"oauth2 required user groups. If multiple groups are configured, the user needs to be least in one group. "+
			"Comma separated list. Example: group1,group2,group3",
	)
	flagSet.TextVar(new(StringSlice),
		"oauth2.validate.roles",
		Defaults.OAuth2.Validate.Roles,
		"oauth2 required user roles. If multiple role are configured, the user needs to be least in one role. "+
			"Comma separated list. Example: role1,role2,role3",
	)
	flagSet.Bool(
		"oauth2.validate.ipaddr",
		Defaults.OAuth2.Validate.IPAddr,
		"validate client ipaddr between VPN and oidc token",
	)
	flagSet.Bool(
		"oauth2.validate.issuer",
		Defaults.OAuth2.Validate.Issuer,
		"validate issuer from oidc discovery",
	)
	flagSet.String(
		"oauth2.validate.common-name",
		Defaults.OAuth2.Validate.CommonName,
		"validate common_name from OpenVPN with IDToken claim. For example: preferred_username or sub",
	)
	flagSet.Bool(
		"oauth2.validate.common-name-case-sensitive",
		Defaults.OAuth2.Validate.CommonNameCaseSensitive,
		"If true, openvpn-auth-oauth2 will validate the common case in sensitive mode",
	)
	flagSet.TextVar(new(StringSlice),
		"oauth2.scopes",
		Defaults.OAuth2.Scopes,
		"oauth2 token scopes. Defaults depends on oauth2.provider. Comma separated list. "+
			"Example: openid,profile,email",
	)
}
