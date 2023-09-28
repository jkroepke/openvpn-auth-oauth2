package config

import (
	"errors"
	"fmt"
	"html/template"
	"net/url"
	"os"
	"reflect"
	"slices"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	flag "github.com/spf13/pflag"
)

type Config struct {
	ConfigFile string   `koanf:"config"`
	Log        *Log     `koanf:"log"`
	Http       *Http    `koanf:"http"`
	OpenVpn    *OpenVpn `koanf:"openvpn"`
	Oauth2     *OAuth2  `koanf:"oauth2"`
}

type Http struct {
	Listen             string             `koanf:"listen"`
	CertFile           string             `koanf:"cert"`
	KeyFile            string             `koanf:"key"`
	Tls                bool               `koanf:"tls"`
	BaseUrl            *url.URL           `koanf:"baseurl"`
	Secret             string             `koanf:"secret"`
	CallbackTemplate   *template.Template `koanf:"callback-template-path"`
	Check              *HttpCheck         `koanf:"check"`
	EnableProxyHeaders bool               `koanf:"enable-proxy-headers"`
}

type HttpCheck struct {
	IpAddr bool `koanf:"ipaddr"`
}

type Log struct {
	Format string `koanf:"format"`
	Level  string `koanf:"level"`
}

type OpenVpn struct {
	Addr          *url.URL       `koanf:"addr"`
	Password      string         `koanf:"password"`
	Bypass        *OpenVpnBypass `koanf:"bypass"`
	AuthTokenUser bool           `koanf:"auth-token-user"`
}

type OpenVpnBypass struct {
	CommonNames []string `koanf:"cn"`
}

type OAuth2 struct {
	Issuer          *url.URL         `koanf:"issuer"`
	Provider        string           `koanf:"provider"`
	AuthorizeParams string           `koanf:"authorize-params"`
	Endpoints       *OAuth2Endpoints `koanf:"endpoint"`
	Client          *OAuth2Client    `koanf:"client"`
	Scopes          []string         `koanf:"scopes"`
	Pkce            bool             `koanf:"pkce"`
	Validate        *OAuth2Validate  `koanf:"validate"`
}

type OAuth2Client struct {
	Id     string `koanf:"id"`
	Secret string `koanf:"secret"`
}

type OAuth2Endpoints struct {
	Discovery *url.URL `koanf:"discovery"`
	Auth      *url.URL `koanf:"auth"`
	Token     *url.URL `koanf:"token"`
}

type OAuth2Validate struct {
	Groups     []string `koanf:"groups"`
	Roles      []string `koanf:"roles"`
	IpAddr     bool     `koanf:"ipaddr"`
	Issuer     bool     `koanf:"issuer"`
	CommonName string   `koanf:"common_name"`
}

func FlagSet() *flag.FlagSet {
	f := flag.NewFlagSet("openvpn-auth-oauth2", flag.ContinueOnError)
	f.Usage = func() {
		fmt.Println("Usage of openvpn-auth-oauth2:")
		f.PrintDefaults()
		os.Exit(0)
	}

	f.String("config", "", "path to one .yaml config files. (env: CONFIG_CONFIG)")
	f.String("log.format", "json", "log format. json or console (env: CONFIG_LOG_FORMAT)")
	f.String("log.level", "info", "log level. (env: CONFIG_LOG_LEVEL)")
	f.String("http.listen", ":9000", "listen addr for client listener. (env: CONFIG_HTTP_LISTEN)")
	f.Bool("http.tls", false, "enable TLS listener. (env: CONFIG_HTTP_TLS)")
	f.String("http.baseurl", "http://localhost:9000", "listen addr for client listener. (env: CONFIG_HTTP_BASEURL)")
	f.String("http.secret", "", "Cookie secret. (env: CONFIG_HTTP_SECRET)")
	f.String("http.key", "", "Path to tls server key. (env: CONFIG_HTTP_KEY)")
	f.String("http.cert", "", "Path to tls server certificate. (env: CONFIG_HTTP_CERT)")
	f.String("http.callback-template-path", "", "Path to a HTML file which is displayed at the end of the screen. (env: CONFIG_HTTP_CALLBACK_TEMPLATE_PATH)")
	f.Bool("http.check.ipaddr", false, "Check if client IP in http and VPN is equal. (env: CONFIG_HTTP_CHECK_IPADDR)")
	f.Bool("http.enable-proxy-headers", false, "Use X-Forward-For http header for client ips. (env: CONFIG_HTTP_ENABLE_PROXY_HEADERS)")
	f.String("openvpn.addr", "unix:///run/openvpn/server.sock", "openvpn management interface addr. Must start with unix:// or tcp:// (env: CONFIG_OPENVPN_ADDR)")
	f.String("openvpn.password", "", "openvpn management interface password. (env: CONFIG_OPENVPN_PASSWORD)")
	f.Bool("openvpn.auth-token-user", true, "Define auth-token-user for all sessions. (env: CONFIG_OPENVPN_AUTH_TOKEN_USER)")
	f.StringSlice("openvpn.bypass.cn", []string{}, "bypass oauth authentication for CNs. (env: CONFIG_OAUTH2_BYPASS_CN)")
	f.String("oauth2.issuer", "", "oauth2 issuer. (env: CONFIG_OAUTH2_ISSUER)")
	f.String("oauth2.provider", "generic", "oauth2 provider. (env: CONFIG_OAUTH2_PROVIDER)")
	f.String("oauth2.authorize-params", "", "additional url query parameter to authorize endpoint. (env: CONFIG_OAUTH2_AUTHORIZE_ENDPOINT)")
	f.String("oauth2.endpoint.discovery", "", "custom oauth2 discovery url. (env: CONFIG_OAUTH2_ENDPOINT_DISCOVERY)")
	f.String("oauth2.endpoint.auth", "", "custom oauth2 auth endpoint. (env: CONFIG_OAUTH2_ENDPOINT_AUTH)")
	f.String("oauth2.endpoint.token", "", "custom oauth2 token endpoint. (env: CONFIG_OAUTH2_ENDPOINT_TOKEN)")
	f.String("oauth2.client.id", "", "oauth2 client id. (env: CONFIG_OAUTH2_CLIENT_ID)")
	f.String("oauth2.client.secret", "", "oauth2 client secret. (env: CONFIG_OAUTH2_CLIENT_SECRET)")
	f.StringSlice("oauth2.validate.groups", []string{}, "oauth2 required user groups. (env: CONFIG_OAUTH2_VALIDATE_GROUPS)")
	f.StringSlice("oauth2.validate.roles", []string{}, "oauth2 required user roles. (env: CONFIG_OAUTH2_VALIDATE_ROLES)")
	f.Bool("oauth2.validate.ipaddr", false, "validate client ipaddr between VPN and OIDC token. (env: CONFIG_OAUTH2_VALIDATE_IPADDR)")
	f.Bool("oauth2.validate.issuer", true, "validate issuer from oidc discovery. (env: CONFIG_OAUTH2_VALIDATE_ISSUER)")
	f.String("oauth2.validate.common_name", "", "validate common_name from OpenVPN with IDToken claim. (env: CONFIG_OAUTH2_VALIDATE_COMMON_NAME)")
	f.StringSlice("oauth2.scopes", []string{"openid", "profile"}, "oauth2 token scopes. (env: CONFIG_OAUTH2_SCOPES)")
	f.Bool("version", false, "shows versions")

	return f
}

func Validate(conf *Config) error {
	for key, value := range map[string]any{
		"http":    conf.Http,
		"oauth2":  conf.Oauth2,
		"openvpn": conf.OpenVpn,
		"log":     conf.Log,
	} {
		if reflect.ValueOf(value).IsNil() {
			return errors.New(utils.StringConcat(key, " is nil"))
		}
	}

	for key, value := range map[string]any{
		"http.check":       conf.Http.Check,
		"oauth2.client":    conf.Oauth2.Client,
		"oauth2.endpoints": conf.Oauth2.Endpoints,
		"oauth2.validate":  conf.Oauth2.Validate,
		"openvpn.bypass":   conf.OpenVpn.Bypass,
	} {
		if reflect.ValueOf(value).IsNil() {
			return errors.New(utils.StringConcat(key, " is nil"))
		}
	}

	for key, value := range map[string]string{
		"http.secret":      conf.Http.Secret,
		"oauth2.client.id": conf.Oauth2.Client.Id,
	} {
		if value == "" {
			return errors.New(utils.StringConcat(key, " is required"))
		}
	}

	for key, value := range map[string]*url.URL{
		"http.baseurl":  conf.Http.BaseUrl,
		"oauth2.issuer": conf.Oauth2.Issuer,
	} {
		if utils.IsUrlEmpty(value) {
			return errors.New(utils.StringConcat(key, " is required"))
		}
	}

	if !slices.Contains([]int{16, 24, 32}, len(conf.Http.Secret)) {
		return errors.New("http.secret requires a length of 16, 24 or 32")
	}

	if !slices.Contains([]string{"tcp", "unix"}, conf.OpenVpn.Addr.Scheme) {
		return errors.New("openvpn.addr: invalid URL. only tcp://addr or unix://addr scheme supported")
	}

	for key, uri := range map[string]*url.URL{
		"http.baseurl":              conf.Http.BaseUrl,
		"oauth2.issuer":             conf.Oauth2.Issuer,
		"oauth2.endpoint.discovery": conf.Oauth2.Endpoints.Discovery,
		"oauth2.endpoint.token":     conf.Oauth2.Endpoints.Token,
		"oauth2.endpoint.auth":      conf.Oauth2.Endpoints.Auth,
	} {
		if utils.IsUrlEmpty(uri) {
			continue
		}

		if !slices.Contains([]string{"http", "https"}, uri.Scheme) {
			return errors.New(utils.StringConcat(key, ": invalid URL. only http:// or https:// scheme supported"))
		}
	}

	return nil
}
