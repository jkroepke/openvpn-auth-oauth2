package config

import (
	"errors"
	"fmt"
	"os"
	"slices"

	flag "github.com/spf13/pflag"
)

type Config struct {
	ConfigFile string  `koanf:"configfile"`
	Log        Log     `koanf:"log"`
	Http       Http    `koanf:"http"`
	OpenVpn    OpenVpn `koanf:"openvpn"`
	Oauth2     OAuth2  `koanf:"oauth2"`
}

type Http struct {
	Listen        string `koanf:"listen"`
	CertFile      string `koanf:"cert"`
	KeyFile       string `koanf:"key"`
	Tls           bool   `koanf:"tls"`
	BaseUrl       string `koanf:"baseurl"`
	SessionSecret string `koanf:"sessionsecret"`
}

type Log struct {
	Level string `koanf:"level"`
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
	Issuer   string         `koanf:"issuer"`
	Client   OAuth2Client   `koanf:"client"`
	Scopes   []string       `koanf:"scopes"`
	Pkce     bool           `koanf:"pkce"`
	Validate OAuth2Validate `koanf:"validate"`
}

type OAuth2Client struct {
	Id     string `koanf:"id"`
	Secret string `koanf:"secret"`
}

type OAuth2Validate struct {
	Groups     []string `koanf:"groups"`
	Roles      []string `koanf:"roles"`
	IpAddr     bool     `koanf:"ipaddr"`
	Issuer     bool     `koanf:"issuer"`
	CommonName string   `koanf:"commonname"`
}

func FlagSet() *flag.FlagSet {
	f := flag.NewFlagSet("openvpn-auth-oauth2", flag.ContinueOnError)
	f.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage of openvpn-auth-oauth2:")
		f.PrintDefaults()
		os.Exit(0)
	}

	f.String("configfile", "", "path to one .yaml config files. (env: CONFIG_CONFIGFILE)")
	f.String("http.listen", ":9000", "listen addr for client listener. (env: CONFIG_HTTP_LISTEN)")
	f.Bool("http.tls", false, "enable TLS listener. (env: CONFIG_HTTP_TLS)")
	f.String("http.baseurl", "http://localhost:9000", "listen addr for client listener. (env: CONFIG_HTTP_BASEURL)")
	f.String("http.sessionsecret", "", "Secret crypt session tokens. (env: CONFIG_HTTP_SESSIONSECRET)")
	f.String("http.key", "", "Path to tls server key. (env: CONFIG_HTTP_KEY)")
	f.String("http.cert", "", "Path to tls server certificate. (env: CONFIG_HTTP_CERT)")
	f.String("openvpn.addr", "127.0.0.1:54321", "openvpn management interface addr. (env: CONFIG_OPENVPN_ADDR)")
	f.String("openvpn.password", "", "openvpn management interface password. (env: CONFIG_OPENVPN_PASSWORD)")
	f.StringSlice("oauth2.bypass.cn", []string{}, "bypass oauth authentication for CNs. (env: CONFIG_OAUTH2_BYPASS_CN)")
	f.String("oauth2.issuer", "", "oauth2 issuer. (env: CONFIG_OAUTH2_ISSUER)")
	f.String("oauth2.client.id", "", "oauth2 client id. (env: CONFIG_OAUTH2_CLIENT_ID)")
	f.String("oauth2.client.secret", "", "oauth2 client secret. (env: CONFIG_OAUTH2_CLIENT_SECRET)")
	f.StringSlice("oauth2.validate.groups", []string{}, "oauth2 required user groups. (env: CONFIG_OAUTH2_VALIDATE_GROUPS)")
	f.StringSlice("oauth2.validate.roles", []string{}, "oauth2 required user roles. (env: CONFIG_OAUTH2_VALIDATE_ROLES)")
	f.Bool("oauth2.validate.ipaddr", false, "validate client ipaddr between VPN and OIDC token. (env: CONFIG_OAUTH2_VALIDATE_IPADDR)")
	f.Bool("oauth2.validate.issuer", true, "validate issuer from oidc discovery. (env: CONFIG_OAUTH2_VALIDATE_ISSUER)")
	f.String("oauth2.validate.commonname", "", "validate common_name from OpenVPN with IDToken claim. (env: CONFIG_OAUTH2_VALIDATE_COMMONNAME)")
	f.StringSlice("oauth2.scopes", []string{"openid", "profile", "offline_access"}, "oauth2 token scopes. (env: CONFIG_OAUTH2_SCOPES)")

	return f
}

func Validate(conf *Config) error {
	if conf.Http.SessionSecret == "" {
		return errors.New("http.sessionsecret is required")
	}

	if !slices.Contains([]int{16, 24, 32}, len(conf.Http.SessionSecret)) {
		return errors.New("http.sessionsecret requires a length of 16, 24 or 32")
	}

	if conf.Oauth2.Issuer == "" {
		return errors.New("oauth2.issuer is required")
	}

	if conf.Oauth2.Client.Id == "" {
		return errors.New("oauth2.client.id is required")
	}

	return nil
}
