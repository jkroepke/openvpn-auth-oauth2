package config

import (
	"errors"
	"fmt"
	"html/template"
	"net/url"
	"os"
	"slices"

	flag "github.com/spf13/pflag"
)

type Config struct {
	ConfigFile string  `koanf:"config"`
	Log        Log     `koanf:"log"`
	Http       Http    `koanf:"http"`
	OpenVpn    OpenVpn `koanf:"openvpn"`
	Oauth2     OAuth2  `koanf:"oauth2"`
}

type Http struct {
	Listen               string `koanf:"listen"`
	CertFile             string `koanf:"cert"`
	KeyFile              string `koanf:"key"`
	Tls                  bool   `koanf:"tls"`
	BaseUrl              string `koanf:"baseurl"`
	Secret               string `koanf:"secret"`
	CallbackTemplate     *template.Template
	CallbackTemplatePath string `koanf:"callback_template_path"`
}

type Log struct {
	Format string `koanf:"format"`
	Level  string `koanf:"level"`
}

type OpenVpn struct {
	Addr     string        `koanf:"addr"`
	Password string        `koanf:"password"`
	Bypass   OpenVpnBypass `koanf:"bypass"`
}

type OpenVpnBypass struct {
	CommonNames []string `koanf:"cn"`
}

type OAuth2 struct {
	Issuer    string          `koanf:"issuer"`
	Endpoints OAuth2Endpoints `koanf:"endpoint"`
	Client    OAuth2Client    `koanf:"client"`
	Scopes    []string        `koanf:"scopes"`
	Pkce      bool            `koanf:"pkce"`
	Validate  OAuth2Validate  `koanf:"validate"`
}

type OAuth2Client struct {
	Id     string `koanf:"id"`
	Secret string `koanf:"secret"`
}

type OAuth2Endpoints struct {
	Discovery string `koanf:"discovery"`
	Auth      string `koanf:"auth"`
	Token     string `koanf:"token"`
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
		_, _ = fmt.Fprintln(os.Stderr, "Usage of openvpn-auth-oauth2:")
		f.PrintDefaults()
		os.Exit(0)
	}

	f.String("config", "", "path to one .yaml config files. (env: CONFIG_CONFIG)")
	f.String("log.format", "json", "log format. json or console (env: CONFIG_LOG_FORMAT)")
	f.String("log.level", "info", "log level. (env: CONFIG_LOG_LEVEL)")
	f.String("http.listen", ":9000", "listen addr for client listener. (env: CONFIG_HTTP_LISTEN)")
	f.Bool("http.tls", false, "enable TLS listener. (env: CONFIG_HTTP_TLS)")
	f.String("http.baseurl", "http://localhost:9000", "listen addr for client listener. (env: CONFIG_HTTP_BASE_URL)")
	f.String("http.secret", "", "Cookie secret. (env: CONFIG_HTTP_SECRET)")
	f.String("http.key", "", "Path to tls server key. (env: CONFIG_HTTP_KEY)")
	f.String("http.cert", "", "Path to tls server certificate. (env: CONFIG_HTTP_CERT)")
	f.String("http.callback_template_path", "", "Path to a HTML file which is displayed at the end of the screen. (env: CONFIG_HTTP_CALLBACK_TEMPLATE_PATH)")
	f.String("openvpn.addr", "tcp://127.0.0.1:54321", "openvpn management interface addr. (env: CONFIG_OPENVPN_ADDR)")
	f.String("openvpn.password", "", "openvpn management interface password. (env: CONFIG_OPENVPN_PASSWORD)")
	f.StringSlice("oauth2.bypass.cn", []string{}, "bypass oauth authentication for CNs. (env: CONFIG_OAUTH2_BYPASS_CN)")
	f.String("oauth2.issuer", "", "oauth2 issuer. (env: CONFIG_OAUTH2_ISSUER)")
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
	for key, value := range map[string]string{
		"http.baseurl":     conf.Http.BaseUrl,
		"http.secret":      conf.Http.Secret,
		"oauth2.issuer":    conf.Oauth2.Issuer,
		"oauth2.client.id": conf.Oauth2.Client.Id,
	} {
		if value == "" {
			return fmt.Errorf("%s is required", key)
		}
	}

	if !slices.Contains([]int{16, 24, 32}, len(conf.Http.Secret)) {
		return errors.New("http.secret requires a length of 16, 24 or 32")
	}

	if uri, err := url.Parse(conf.OpenVpn.Addr); err != nil {
		return fmt.Errorf("openvpn.addr: invalid URL. error: %s", err)
	} else if !slices.Contains([]string{"tcp", "unix"}, uri.Scheme) {
		return errors.New("openvpn.addr: invalid URL. only tcp://addr or unix://addr scheme supported")
	}

	for key, value := range map[string]string{
		"http.baseurl":              conf.Http.BaseUrl,
		"oauth2.issuer":             conf.Oauth2.Issuer,
		"oauth2.endpoint.discovery": conf.Oauth2.Endpoints.Discovery,
		"oauth2.endpoint.token":     conf.Oauth2.Endpoints.Token,
		"oauth2.endpoint.auth":      conf.Oauth2.Endpoints.Auth,
	} {
		if value == "" {
			continue
		}

		uri, err := url.Parse(value)

		if err != nil {
			return fmt.Errorf("%s: invalid URL. error: %s", key, err)
		}

		if !slices.Contains([]string{"http", "https"}, uri.Scheme) {
			return fmt.Errorf("%s: invalid URL. only http:// or https:// scheme supported", key)
		}
	}

	if (conf.Oauth2.Endpoints.Token != "" && conf.Oauth2.Endpoints.Auth == "") ||
		(conf.Oauth2.Endpoints.Token == "" && conf.Oauth2.Endpoints.Auth != "") {
		return errors.New("both oauth2.endpoints.tokenUrl and oauth2.endpoints.authUrl are required")
	}

	if conf.Http.CallbackTemplatePath != "" {
		tmpl, err := template.New("callback").ParseFiles(conf.Http.CallbackTemplatePath)
		if err != nil {
			return fmt.Errorf("http.callbackTemplatePath: invalid template: %s", err)
		}

		conf.Http.CallbackTemplate = tmpl
	}

	return nil
}
