package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	flag "github.com/spf13/pflag"
)

const (
	Plugin = iota
	ManagementClient
)

// FlagSet configure the command line parser using the [flag] library.
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
		"path to one .yaml config files",
	)
	flagSet.String(
		"log.format",
		Defaults.Log.Format,
		"log format. json or console",
	)
	flagSet.String(
		"log.level",
		Defaults.Log.Level,
		"log level",
	)
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
	flagSet.String(
		"http.secret",
		Defaults.HTTP.Secret,
		"Cookie secret",
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
		"openvpn.addr",
		Defaults.OpenVpn.Addr.String(),
		"openvpn management interface addr. Must start with unix:// or tcp://",
	)
	flagSet.String(
		"openvpn.password",
		Defaults.OpenVpn.Password,
		"openvpn management interface password",
	)
	flagSet.Bool(
		"openvpn.auth-token-user",
		Defaults.OpenVpn.AuthTokenUser,
		"Define auth-token-user for all sessions",
	)
	flagSet.String(
		"openvpn.auth-pending-timeout",
		Defaults.OpenVpn.AuthPendingTimeout.String(),
		"How long OpenVPN server wait until user is authenticated",
	)
	flagSet.StringSlice(
		"openvpn.bypass.cn",
		Defaults.OpenVpn.Bypass.CommonNames,
		"bypass oauth authentication for CNs",
	)
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
		"custom oauth2 discovery url",
	)
	flagSet.String(
		"oauth2.endpoint.auth",
		Defaults.OAuth2.Endpoints.Auth.String(),
		"custom oauth2 auth endpoint",
	)
	flagSet.String(
		"oauth2.endpoint.token",
		Defaults.OAuth2.Endpoints.Token.String(),
		"custom oauth2 token endpoint",
	)
	flagSet.String(
		"oauth2.client.id",
		Defaults.OAuth2.Client.ID,
		"oauth2 client id",
	)
	flagSet.String(
		"oauth2.client.secret",
		Defaults.OAuth2.Client.Secret,
		"oauth2 client secret",
	)
	flagSet.StringSlice(
		"oauth2.validate.groups",
		Defaults.OAuth2.Validate.Groups,
		"oauth2 required user groups",
	)
	flagSet.StringSlice(
		"oauth2.validate.roles",
		Defaults.OAuth2.Validate.Roles,
		"oauth2 required user roles",
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
		"validate common_name from OpenVPN with IDToken claim",
	)
	flagSet.StringSlice(
		"oauth2.scopes",
		Defaults.OAuth2.Scopes,
		"oauth2 token scopes. Defaults depends on oauth2.provider",
	)
	flagSet.Bool(
		"version",
		false,
		"show version",
	)

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

// Validate validates the config.
func Validate(mode int, conf Config) error { //nolint:cyclop
	for key, value := range map[string]string{
		"http.secret":      conf.HTTP.Secret,
		"oauth2.client.id": conf.OAuth2.Client.ID,
	} {
		if value == "" {
			return fmt.Errorf("%s is %w", key, ErrRequired)
		}
	}

	for key, value := range map[string]*url.URL{
		"http.baseurl":  conf.HTTP.BaseURL,
		"oauth2.issuer": conf.OAuth2.Issuer,
	} {
		if utils.IsURLEmpty(value) {
			return fmt.Errorf("%s is %w", key, ErrRequired)
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
				return fmt.Errorf("%s is %w", key, ErrRequired)
			}
		}

		if !slices.Contains([]string{"tcp", "unix"}, conf.OpenVpn.Addr.Scheme) {
			return errors.New("openvpn.addr: invalid URL. only tcp://addr or unix://addr scheme supported")
		}
	}

	return nil
}
