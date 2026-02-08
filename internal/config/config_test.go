package config_test

import (
	"bytes"
	"flag"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"testing"
	"text/template"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	oauth2types "github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

//goland:noinspection RegExpUnnecessaryNonCapturingGroup
func TestConfig(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		configFile string
		conf       config.Config
		err        error
	}{
		{
			"empty file",
			"",
			config.Defaults,
			nil,
		},
		{
			"minimal file",
			// language=yaml
			`
oauth2:
    issuer: "https://company.zitadel.cloud"
    client:
        id: "test"
        secret: "test"
http:
    secret: "1jd93h5b6s82lf03jh5b2hf9"
`,
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = "1jd93h5b6s82lf03jh5b2hf9"
				conf.OAuth2.Issuer = &url.URL{
					Scheme: "https",
					Host:   "company.zitadel.cloud",
				}
				conf.OAuth2.Client.ID = "test"
				conf.OAuth2.Client.Secret = "test"

				return conf
			}(),
			nil,
		},
		{
			"full file",
			// language=yaml
			`
debug:
    pprof: true
    listen: :9002
log:
    format: json
    level: DEBUG
    vpn-client-ip: false
oauth2:
    issuer: "https://company.zitadel.cloud"
    client:
        id: "test"
        secret: "test"
        private-key-id: "openvpn-auth-oauth2"
    validate:
        common-name: "preffered_username"
        common-name-case-sensitive: true
        groups:
        - "test"
        - "test2"
        roles:
        - "test"
        - "test2"
        ipaddr: true
        issuer: false
    authorize-params: "a=c"
    auth-style: "AuthStyleInHeader"
    scopes:
    - "openid"
    - "profile"
    nonce: true
    pkce: false
    user-info: true
    groups-claim: groups_direct
    refresh:
        enabled: true
        expires: 10h0m0s
        secret: "1jd93h5b6s82lf03jh5b2hf9"
        use-session-id: true
        validate-user: true
    openvpn-username-claim: "sub"
    openvpn-username-cel: "{{ index . 0 }}"
openvpn:
    addr: "unix:///run/openvpn/server2.sock"
    auth-token-user: true
    auth-pending-timeout: 2m
    override-username: true
    bypass:
        common-names:
        - "test"
        - "test2"
    client-config:
        enabled: true
        token-claim: sub
        path: "."
        user-selector:
            enabled: true
            static-values:
            - "default"
    common-name:
        environment-variable-name: X509_0_emailAddress
        mode: omit
    password: "1jd93h5b6s82lf03jh5b2hf9"
    pass-through:
        address: "unix:///run/openvpn/pass-through.sock"
        enabled: true
        password: "password"
        socket-group: "group"
        socket-mode: 0666
    reauthentication: false
http:
    listen: ":9001"
    secret: "1jd93h5b6s82lf03jh5b2hf9"
    enable-proxy-headers: false
    short-url: false
    assets-path: "."
    template: "../../README.md"
    check:
        ipaddr: true
`,
			config.Config{
				Debug: config.Debug{
					Pprof:  true,
					Listen: ":9002",
				},
				Log: config.Log{
					Format:      "json",
					Level:       slog.LevelDebug,
					VPNClientIP: false,
				},
				HTTP: config.HTTP{
					AssetPath: os.DirFS("."),
					BaseURL: &url.URL{
						Scheme: "http",
						Host:   "localhost:9000",
					},
					Check: config.HTTPCheck{
						IPAddr: true,
					},
					EnableProxyHeaders: false,
					ShortURL:           false,
					Listen:             ":9001",
					Secret:             "1jd93h5b6s82lf03jh5b2hf9",
					Template: func() *template.Template {
						filePath := "../../README.md"
						tmpl, err := template.New(path.Base(filePath)).ParseFiles(filePath)
						require.NoError(t, err)

						return tmpl
					}(),
				},
				OpenVPN: config.OpenVPN{
					Addr: &url.URL{
						Scheme:   "unix",
						Path:     "/run/openvpn/server2.sock",
						OmitHost: false,
					},
					Bypass: config.OpenVPNBypass{
						CommonNames: []*regexp.Regexp{regexp.MustCompile(`^(?:test)$`), regexp.MustCompile(`^(?:test2)$`)},
					},
					ClientConfig: config.OpenVPNConfig{
						Enabled:    true,
						TokenClaim: "sub",
						Path:       os.DirFS("."),
						UserSelector: config.OpenVPNConfigProfileSelector{
							Enabled:      true,
							StaticValues: []string{"default"},
						},
					},
					Password:           "1jd93h5b6s82lf03jh5b2hf9",
					AuthTokenUser:      true,
					AuthPendingTimeout: 2 * time.Minute,
					OverrideUsername:   true,
					CommonName: config.OpenVPNCommonName{
						EnvironmentVariableName: "X509_0_emailAddress",
						Mode:                    config.CommonNameModeOmit,
					},
					Passthrough: config.OpenVPNPassthrough{
						Enabled: true,
						Address: &url.URL{
							Scheme:   "unix",
							Path:     "/run/openvpn/pass-through.sock",
							OmitHost: false,
						},
						SocketGroup: "group",
						SocketMode:  0o666,
						Password:    "password",
					},
					CommandTimeout:   10 * time.Second,
					ReAuthentication: false,
				},
				OAuth2: config.OAuth2{
					Issuer: &url.URL{
						Scheme: "https",
						Host:   "company.zitadel.cloud",
					},
					Provider:        "generic",
					AuthorizeParams: "a=c",
					Endpoints: config.OAuth2Endpoints{
						Auth:      &url.URL{},
						Token:     &url.URL{},
						Discovery: &url.URL{},
					},
					Client: config.OAuth2Client{
						ID:           "test",
						Secret:       "test",
						PrivateKeyID: "openvpn-auth-oauth2",
					},
					Nonce:                true,
					PKCE:                 false,
					UserInfo:             true,
					GroupsClaim:          "groups_direct",
					Scopes:               []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile},
					AuthStyle:            config.OAuth2AuthStyle(oauth2.AuthStyleInHeader),
					OpenVPNUsernameClaim: "sub",
					OpenVPNUsernameCEL:   "{{ index . 0 }}",
					Refresh: config.OAuth2Refresh{
						Enabled:      true,
						Expires:      10 * time.Hour,
						Secret:       "1jd93h5b6s82lf03jh5b2hf9",
						UseSessionID: true,
						ValidateUser: true,
					},
					Validate: config.OAuth2Validate{
						CommonName:              "preffered_username",
						CommonNameCaseSensitive: true,
						IPAddr:                  true,
						Issuer:                  false,
						Groups:                  []string{"test", "test2"},
						Roles:                   []string{"test", "test2"},
					},
				},
			},
			nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer

			_ = io.Writer(&buf)

			file, err := os.CreateTemp(t.TempDir(), "openvpn-auth-oauth2-*")
			require.NoError(t, err)

			// close and remove the temporary file at the end of the program.
			t.Cleanup(func() {
				require.NoError(t, file.Close())
				require.NoError(t, os.Remove(file.Name()))
			})

			_, err = file.WriteString(tc.configFile)
			require.NoError(t, err)

			conf, err := config.New([]string{"openvpn-auth-oauth2", "--config", file.Name()}, &buf)
			if tc.err != nil {
				require.Error(t, err)
				assert.Equal(t, tc.err.Error(), err.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.conf, conf)
			}
		})
	}
}

func TestConfigHelpFlag(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	_ = io.Writer(&buf)

	_, err := config.New([]string{"openvpn-auth-oauth2", "--help"}, &buf)

	require.ErrorIs(t, err, flag.ErrHelp)
}

func TestConfigVersionFlag(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	_ = io.Writer(&buf)

	_, err := config.New([]string{"openvpn-auth-oauth2", "--version"}, &buf)

	require.ErrorIs(t, err, config.ErrVersion)
}

func TestConfigFlagSet(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		args         []string
		expectConfig config.Config
	}{
		{
			"--openvpn.bypass.common-names",
			[]string{"--openvpn.bypass.common-names=a,b"},
			func() config.Config {
				conf := config.Defaults
				//goland:noinspection RegExpUnnecessaryNonCapturingGroup
				conf.OpenVPN.Bypass.CommonNames = []*regexp.Regexp{regexp.MustCompile("^(?:a)$"), regexp.MustCompile("^(?:b)$")}

				return conf
			}(),
		},
		{
			"--oauth2.validate.common-name",
			[]string{"--oauth2.validate.common-name=plain"},
			func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Validate.CommonName = "plain"

				return conf
			}(),
		},
		{
			"--openvpn.common-name.mode",
			[]string{"--openvpn.common-name.mode=plain"},
			func() config.Config {
				conf := config.Defaults
				conf.OpenVPN.CommonName.Mode = config.CommonNameModePlain

				return conf
			}(),
		},
		{
			"--http.assets-path",
			[]string{"--http.assets-path=."},
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.AssetPath = os.DirFS(".")

				return conf
			}(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer

			_ = io.Writer(&buf)

			conf, err := config.New(slices.Concat([]string{"openvpn-auth-oauth2"}, tc.args), &buf)

			require.NoError(t, err)
			assert.Equal(t, tc.expectConfig, conf)
		})
	}
}
