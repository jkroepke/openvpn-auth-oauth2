package config_test

import (
	"errors"
	"flag"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestLoad(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name       string
		configFile string
		conf       config.Config
		err        error
	}{
		{
			"empty file",
			"",
			config.Config{},
			errors.New("validation error: oauth2.client.id is required"),
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
				conf.HTTP.CallbackTemplate = nil
				conf.HTTP.Secret = "1jd93h5b6s82lf03jh5b2hf9"
				conf.OAuth2.Issuer = &config.URL{
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
    pkce: true
    refresh:
        enabled: true
        expires: 10h0m0s
        secret: "1jd93h5b6s82lf03jh5b2hf9"
        use-session-id: true
        validate-user: true
openvpn:
    addr: "unix:///run/openvpn/server2.sock"
    auth-token-user: true
    auth-pending-timeout: 2m
    bypass:
        common-names:
        - "test"
        - "test2"
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
http:
    listen: ":9001"
    secret: "1jd93h5b6s82lf03jh5b2hf9"
    enable-proxy-headers: true
    assets-path: "."
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
					Listen:             ":9001",
					EnableProxyHeaders: true,
					Check: config.HTTPCheck{
						IPAddr: true,
					},
					Secret: "1jd93h5b6s82lf03jh5b2hf9",
					BaseURL: &config.URL{
						Scheme: "http",
						Host:   "localhost:9000",
					},
					AssetPath: ".",
				},
				OpenVpn: config.OpenVpn{
					Addr: &config.URL{
						Scheme:   "unix",
						Path:     "/run/openvpn/server2.sock",
						OmitHost: false,
					},
					Bypass: config.OpenVpnBypass{
						CommonNames: []string{"test", "test2"},
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
						Address: &config.URL{
							Scheme:   "unix",
							Path:     "/run/openvpn/pass-through.sock",
							OmitHost: false,
						},
						SocketGroup: "group",
						SocketMode:  0o666,
						Password:    "password",
					},
				},
				OAuth2: config.OAuth2{
					Issuer: &config.URL{
						Scheme: "https",
						Host:   "company.zitadel.cloud",
					},
					Provider: "generic",

					AuthorizeParams: "a=c",
					Endpoints: config.OAuth2Endpoints{
						Auth:      &config.URL{},
						Token:     &config.URL{},
						Discovery: &config.URL{},
					},
					Client: config.OAuth2Client{
						ID:     "test",
						Secret: "test",
					},
					Nonce:     true,
					PKCE:      true,
					Scopes:    []string{"openid", "profile"},
					AuthStyle: config.OAuth2AuthStyle(oauth2.AuthStyleInHeader),
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			file, err := os.CreateTemp(t.TempDir(), "openvpn-auth-oauth2-*")
			require.NoError(t, err)

			// close and remove the temporary file at the end of the program.
			t.Cleanup(func() {
				require.NoError(t, file.Close())
				require.NoError(t, os.Remove(file.Name()))
			})

			_, err = file.WriteString(tt.configFile)
			require.NoError(t, err)

			conf, err := config.Load(config.ManagementClient, file.Name(), flag.NewFlagSet("openvpn-auth-oauth2", flag.ContinueOnError))
			conf.HTTP.CallbackTemplate = nil

			if tt.err != nil {
				require.Error(t, err)
				assert.Equal(t, tt.err.Error(), err.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.conf, conf)
			}
		})
	}
}
