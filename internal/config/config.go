//nolint:lll,goerr113
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

// FlagSet configure the command line parser using [flag] library.
func FlagSet() *flag.FlagSet {
	flagSet := flag.NewFlagSet("openvpn-auth-oauth2", flag.ContinueOnError)
	flagSet.Usage = func() {
		fmt.Println("Usage of openvpn-auth-oauth2:")
		flagSet.PrintDefaults()
		os.Exit(0)
	}

	//nolint: lll
	flagSet.String("config", "", "path to one .yaml config files. (env: CONFIG_CONFIG)")
	flagSet.String("log.format", "console", "log format. json or console (env: CONFIG_LOG_FORMAT)")
	flagSet.String("log.level", "info", "log level. (env: CONFIG_LOG_LEVEL)")
	flagSet.String("http.listen", ":9000", "listen addr for client listener. (env: CONFIG_HTTP_LISTEN)")
	flagSet.Bool("http.tls", false, "enable TLS listener. (env: CONFIG_HTTP_TLS)")
	flagSet.String("http.baseurl", "http://localhost:9000", "listen addr for client listener. (env: CONFIG_HTTP_BASEURL)")
	flagSet.String("http.secret", "", "Cookie secret. (env: CONFIG_HTTP_SECRET)")
	flagSet.String("http.key", "", "Path to tls server key. (env: CONFIG_HTTP_KEY)")
	flagSet.String("http.cert", "", "Path to tls server certificate. (env: CONFIG_HTTP_CERT)")
	flagSet.String("http.callback-template-path", "", "Path to a HTML file which is displayed at the end of the screen. (env: CONFIG_HTTP_CALLBACK_TEMPLATE_PATH)")
	flagSet.Bool("http.check.ipaddr", false, "Check if client IP in http and VPN is equal. (env: CONFIG_HTTP_CHECK_IPADDR)")
	flagSet.Bool("http.enable-proxy-headers", false, "Use X-Forward-For http header for client ips. (env: CONFIG_HTTP_ENABLE_PROXY_HEADERS)")
	flagSet.String("openvpn.addr", "unix:///run/openvpn/server.sock", "openvpn management interface addr. Must start with unix:// or tcp:// (env: CONFIG_OPENVPN_ADDR)")
	flagSet.String("openvpn.password", "", "openvpn management interface password. (env: CONFIG_OPENVPN_PASSWORD)")
	flagSet.Bool("openvpn.auth-token-user", true, "Define auth-token-user for all sessions. (env: CONFIG_OPENVPN_AUTH_TOKEN_USER)")
	flagSet.StringSlice("openvpn.bypass.cn", []string{}, "bypass oauth authentication for CNs. (env: CONFIG_OAUTH2_BYPASS_CN)")
	flagSet.String("oauth2.issuer", "", "oauth2 issuer. (env: CONFIG_OAUTH2_ISSUER)")
	flagSet.String("oauth2.provider", "generic", "oauth2 provider. (env: CONFIG_OAUTH2_PROVIDER)")
	flagSet.String("oauth2.authorize-params", "", "additional url query parameter to authorize endpoint. (env: CONFIG_OAUTH2_AUTHORIZE_ENDPOINT)")
	flagSet.String("oauth2.endpoint.discovery", "", "custom oauth2 discovery url. (env: CONFIG_OAUTH2_ENDPOINT_DISCOVERY)")
	flagSet.String("oauth2.endpoint.auth", "", "custom oauth2 auth endpoint. (env: CONFIG_OAUTH2_ENDPOINT_AUTH)")
	flagSet.String("oauth2.endpoint.token", "", "custom oauth2 token endpoint. (env: CONFIG_OAUTH2_ENDPOINT_TOKEN)")
	flagSet.String("oauth2.client.id", "", "oauth2 client id. (env: CONFIG_OAUTH2_CLIENT_ID)")
	flagSet.String("oauth2.client.secret", "", "oauth2 client secret. (env: CONFIG_OAUTH2_CLIENT_SECRET)")
	flagSet.StringSlice("oauth2.validate.groups", []string{}, "oauth2 required user groups. (env: CONFIG_OAUTH2_VALIDATE_GROUPS)")
	flagSet.StringSlice("oauth2.validate.roles", []string{}, "oauth2 required user roles. (env: CONFIG_OAUTH2_VALIDATE_ROLES)")
	flagSet.Bool("oauth2.validate.ipaddr", false, "validate client ipaddr between VPN and oidc token. (env: CONFIG_OAUTH2_VALIDATE_IPADDR)")
	flagSet.Bool("oauth2.validate.issuer", true, "validate issuer from oidc discovery. (env: CONFIG_OAUTH2_VALIDATE_ISSUER)")
	flagSet.String("oauth2.validate.common_name", "", "validate common_name from OpenVPN with IDToken claim. (env: CONFIG_OAUTH2_VALIDATE_COMMON_NAME)")
	flagSet.StringSlice("oauth2.scopes", []string{"openid", "profile"}, "oauth2 token scopes. (env: CONFIG_OAUTH2_SCOPES)")
	flagSet.Bool("version", false, "shows versions")

	return flagSet
}

// Validate validates the config.
func Validate(conf Config) error {
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

	if !slices.Contains([]string{"tcp", "unix"}, conf.OpenVpn.Addr.Scheme) {
		return errors.New("openvpn.addr: invalid URL. only tcp://addr or unix://addr scheme supported")
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

	return nil
}
