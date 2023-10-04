//nolint:goerr113
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	flag "github.com/spf13/pflag"
)

const (
	Plugin = iota
	ManagementClient
)

// FlagSet configure the command line parser using [flag] library.
func FlagSet() *flag.FlagSet {
	flagSet := flag.NewFlagSet("openvpn-auth-oauth2", flag.ContinueOnError)
	flagSet.Usage = func() {
		fmt.Println("Usage of openvpn-auth-oauth2:")
		flagSet.PrintDefaults()
		os.Exit(0)
	}

	flagSet.String(
		"config",
		"",
		"path to one .yaml config files. (env: CONFIG_CONFIG)",
	)
	flagSet.String(
		"log.format",
		Defaults.Log.Format,
		"log format. json or console (env: CONFIG_LOG_FORMAT)",
	)
	flagSet.String(
		"log.level",
		Defaults.Log.Level,
		"log level. (env: CONFIG_LOG_LEVEL)",
	)
	flagSet.String(
		"http.listen",
		Defaults.HTTP.Listen,
		"listen addr for client listener. (env: CONFIG_HTTP_LISTEN)",
	)
	flagSet.Bool(
		"http.tls",
		Defaults.HTTP.TLS,
		"enable TLS listener. (env: CONFIG_HTTP_TLS)",
	)
	flagSet.String(
		"http.baseurl",
		Defaults.HTTP.BaseURL.String(),
		"listen addr for client listener. (env: CONFIG_HTTP_BASEURL)",
	)
	flagSet.String(
		"http.secret",
		Defaults.HTTP.Secret,
		"Cookie secret. (env: CONFIG_HTTP_SECRET)",
	)
	flagSet.String(
		"http.key",
		Defaults.HTTP.KeyFile,
		"Path to tls server key. (env: CONFIG_HTTP_KEY)",
	)
	flagSet.String(
		"http.cert",
		Defaults.HTTP.CertFile,
		"Path to tls server certificate. (env: CONFIG_HTTP_CERT)",
	)
	flagSet.String(
		"http.callback-template-path",
		"",
		"Path to a HTML file which is displayed at the end of the screen. (env: CONFIG_HTTP_CALLBACK_TEMPLATE_PATH)",
	)
	flagSet.Bool(
		"http.check.ipaddr",
		Defaults.HTTP.Check.IPAddr,
		"Check if client IP in http and VPN is equal. (env: CONFIG_HTTP_CHECK_IPADDR)",
	)
	flagSet.Bool(
		"http.enable-proxy-headers",
		Defaults.HTTP.EnableProxyHeaders,
		"Use X-Forward-For http header for client ips. (env: CONFIG_HTTP_ENABLE_PROXY_HEADERS)",
	)
	flagSet.String(
		"openvpn.addr",
		Defaults.OpenVpn.Addr.String(),
		"openvpn management interface addr. Must start with unix:// or tcp:// (env: CONFIG_OPENVPN_ADDR)",
	)
	flagSet.String(
		"openvpn.password",
		Defaults.OpenVpn.Password,
		"openvpn management interface password. (env: CONFIG_OPENVPN_PASSWORD)",
	)
	flagSet.Bool(
		"openvpn.auth-token-user",
		Defaults.OpenVpn.AuthTokenUser,
		"Define auth-token-user for all sessions. (env: CONFIG_OPENVPN_AUTH_TOKEN_USER)",
	)
	flagSet.StringSlice(
		"openvpn.bypass.cn",
		Defaults.OpenVpn.Bypass.CommonNames,
		"bypass oauth authentication for CNs. (env: CONFIG_OAUTH2_BYPASS_CN)",
	)
	flagSet.String(
		"oauth2.issuer",
		Defaults.OAuth2.Issuer.String(),
		"oauth2 issuer. (env: CONFIG_OAUTH2_ISSUER)",
	)
	flagSet.String(
		"oauth2.provider",
		Defaults.OAuth2.Provider,
		"oauth2 provider. (env: CONFIG_OAUTH2_PROVIDER)",
	)
	flagSet.String(
		"oauth2.authorize-params",
		"",
		"additional url query parameter to authorize endpoint. (env: CONFIG_OAUTH2_AUTHORIZE_ENDPOINT)",
	)
	flagSet.String(
		"oauth2.endpoint.discovery",
		Defaults.OAuth2.Endpoints.Discovery.String(),
		"custom oauth2 discovery url. (env: CONFIG_OAUTH2_ENDPOINT_DISCOVERY)",
	)
	flagSet.String(
		"oauth2.endpoint.auth",
		Defaults.OAuth2.Endpoints.Auth.String(),
		"custom oauth2 auth endpoint. (env: CONFIG_OAUTH2_ENDPOINT_AUTH)",
	)
	flagSet.String(
		"oauth2.endpoint.token",
		Defaults.OAuth2.Endpoints.Token.String(),
		"custom oauth2 token endpoint. (env: CONFIG_OAUTH2_ENDPOINT_TOKEN)",
	)
	flagSet.String(
		"oauth2.client.id",
		Defaults.OAuth2.Client.ID,
		"oauth2 client id. (env: CONFIG_OAUTH2_CLIENT_ID)",
	)
	flagSet.String(
		"oauth2.client.secret",
		Defaults.OAuth2.Client.Secret,
		"oauth2 client secret. (env: CONFIG_OAUTH2_CLIENT_SECRET)",
	)
	flagSet.StringSlice(
		"oauth2.validate.groups",
		Defaults.OAuth2.Validate.Groups,
		"oauth2 required user groups. (env: CONFIG_OAUTH2_VALIDATE_GROUPS)",
	)
	flagSet.StringSlice(
		"oauth2.validate.roles",
		Defaults.OAuth2.Validate.Roles,
		"oauth2 required user roles. (env: CONFIG_OAUTH2_VALIDATE_ROLES)",
	)
	flagSet.Bool(
		"oauth2.validate.ipaddr",
		Defaults.OAuth2.Validate.IPAddr,
		"validate client ipaddr between VPN and oidc token. (env: CONFIG_OAUTH2_VALIDATE_IPADDR)",
	)
	flagSet.Bool(
		"oauth2.validate.issuer",
		Defaults.OAuth2.Validate.Issuer,
		"validate issuer from oidc discovery. (env: CONFIG_OAUTH2_VALIDATE_ISSUER)",
	)
	flagSet.String(
		"oauth2.validate.common_name",
		Defaults.OAuth2.Validate.CommonName,
		"validate common_name from OpenVPN with IDToken claim. (env: CONFIG_OAUTH2_VALIDATE_COMMON_NAME)",
	)
	flagSet.StringSlice(
		"oauth2.scopes",
		Defaults.OAuth2.Scopes,
		"oauth2 token scopes. (env: CONFIG_OAUTH2_SCOPES)",
	)
	flagSet.Bool(
		"version",
		false,
		"shows versions",
	)

	return flagSet
}

// Validate validates the config.
func Validate(mode int, conf Config) error { //nolint:cyclop
	for key, value := range map[string]string{
		"http.secret":      conf.HTTP.Secret,
		"oauth2.client.id": conf.OAuth2.Client.ID,
	} {
		if value == "" {
			return fmt.Errorf("%s is required", key)
		}
	}

	for key, value := range map[string]*url.URL{
		"http.baseurl":  conf.HTTP.BaseURL,
		"oauth2.issuer": conf.OAuth2.Issuer,
	} {
		if utils.IsURLEmpty(value) {
			return errors.New(utils.StringConcat(key, " is required"))
		}
	}

	if !slices.Contains([]int{16, 24, 32}, len(conf.HTTP.Secret)) {
		return errors.New("http.secret requires a length of 16, 24 or 32")
	}

	for key, uri := range map[string]*url.URL{
		"http.baseurl":              conf.HTTP.BaseURL,
		"oauth2.issuer":             conf.OAuth2.Issuer,
		"oauth2.endpoint.discovery": conf.OAuth2.Endpoints.Discovery,
		"oauth2.endpoint.token":     conf.OAuth2.Endpoints.Token,
		"oauth2.endpoint.auth":      conf.OAuth2.Endpoints.Auth,
	} {
		if utils.IsURLEmpty(uri) {
			continue
		}

		if !slices.Contains([]string{"http", "https"}, uri.Scheme) {
			return errors.New(utils.StringConcat(key, ": invalid URL. only http:// or https:// scheme supported"))
		}
	}

	if mode == ManagementClient {
		for key, value := range map[string]*url.URL{
			"openvpn.addr": conf.OpenVpn.Addr,
		} {
			if utils.IsURLEmpty(value) {
				return errors.New(utils.StringConcat(key, " is required"))
			}
		}

		if !slices.Contains([]string{"tcp", "unix"}, conf.OpenVpn.Addr.Scheme) {
			return errors.New("openvpn.addr: invalid URL. only tcp://addr or unix://addr scheme supported")
		}
	}

	return nil
}
