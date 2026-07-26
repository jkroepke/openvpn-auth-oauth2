package config_test

import (
	"bytes"
	"flag"
	"io"
	"log/slog"
	"net/url"
	"os"
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config/types"
	oauth2types "github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/test/testsuite"
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
				conf.OAuth2.Issuer = types.URL{URL: &url.URL{
					Scheme: "https",
					Host:   "company.zitadel.cloud",
				}}
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
        groups:
        - "test"
        - "test2"
        expression: "openvpn.commonName == token.claims.preferred_username"
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
    openvpn-username: "token.claims.sub"
openvpn:
    addr: "unix:///run/openvpn/server2.sock"
    auth-token-user: true
    auth-pending-timeout: 2m
    command-timeout: 15s
    enforce-unique-user: true
    override-username: true
    bypass:
        common-names:
        - "test"
        - "test2"
    client-config:
        enabled: true
        ignore-not-found: false
        path: "."
        strategy: user-selector
        expression: |
            ["default", string(token.claims.sub)]
    common-name:
        environment-variable-name: X509_0_emailAddress
    password: "1jd93h5b6s82lf03jh5b2hf9"
    pass-through:
        address: "unix:///run/openvpn/pass-through.sock"
        enabled: true
        password: "password"
        socket-group: "group"
        socket-mode: "0666"
    reauthentication: false
http:
    listen: ":9001"
    secret: "1jd93h5b6s82lf03jh5b2hf9"
    enable-proxy-headers: false
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
					AssetPath: func() types.FS {
						dirFS, err := types.NewFS(".")
						require.NoError(t, err)

						return dirFS
					}(),
					BaseURL: types.URL{URL: &url.URL{
						Scheme: "http",
						Host:   "localhost:9000",
					}},
					Check: config.HTTPCheck{
						IPAddr: true,
					},
					EnableProxyHeaders: false,
					TrustedProxies:     types.StringSlice{},
					Listen:             ":9001",
					Secret:             "1jd93h5b6s82lf03jh5b2hf9",
					Template: func() types.Template {
						tmpl, err := types.NewTemplate("../../README.md")
						require.NoError(t, err)

						return tmpl
					}(),
				},
				OpenVPN: config.OpenVPN{
					Addr: types.URL{URL: &url.URL{
						Scheme:   "unix",
						Path:     "/run/openvpn/server2.sock",
						OmitHost: false,
					}},
					Bypass: config.OpenVPNBypass{
						CommonNames: types.RegexpSlice{regexp.MustCompile(`^(?:test)$`), regexp.MustCompile(`^(?:test2)$`)},
					},
					ClientConfig: config.OpenVPNConfig{
						Enabled:  true,
						Strategy: config.OpenVPNConfigStrategyUserSelector,
						Path: func() types.FS {
							dirFS, err := types.NewFS(".")
							require.NoError(t, err)

							return dirFS
						}(),
						Expression: "[\"default\", string(token.claims.sub)]\n",
					},
					Password:           "1jd93h5b6s82lf03jh5b2hf9",
					AuthTokenUser:      true,
					AuthPendingTimeout: 2 * time.Minute,
					EnforceUniqueUser:  true,
					OverrideUsername:   true,
					CommonName: config.OpenVPNCommonName{
						EnvironmentVariableName: "X509_0_emailAddress",
					},
					Passthrough: config.OpenVPNPassthrough{
						Enabled: true,
						Address: types.URL{URL: &url.URL{
							Scheme:   "unix",
							Path:     "/run/openvpn/pass-through.sock",
							OmitHost: false,
						}},
						SocketGroup: "group",
						SocketMode:  types.FileMode(0o666),
						Password:    "password",
					},
					CommandTimeout:   15 * time.Second,
					ReAuthentication: false,
				},
				OAuth2: config.OAuth2{
					Issuer: types.URL{URL: &url.URL{
						Scheme: "https",
						Host:   "company.zitadel.cloud",
					}},
					Provider:        "generic",
					AuthorizeParams: "a=c",
					Endpoints: config.OAuth2Endpoints{
						Auth:      types.URL{URL: &url.URL{}},
						Token:     types.URL{URL: &url.URL{}},
						Discovery: types.URL{URL: &url.URL{}},
					},
					Client: config.OAuth2Client{
						ID:           "test",
						Secret:       "test",
						PrivateKeyID: "openvpn-auth-oauth2",
					},
					Nonce:           true,
					PKCE:            false,
					UserInfo:        true,
					GroupsClaim:     "groups_direct",
					Scopes:          []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile},
					AuthStyle:       config.OAuth2AuthStyle(oauth2.AuthStyleInHeader),
					OpenVPNUsername: "token.claims." + testsuite.SubjectClaim,
					Refresh: config.OAuth2Refresh{
						Enabled:      true,
						Expires:      10 * time.Hour,
						Secret:       "1jd93h5b6s82lf03jh5b2hf9",
						UseSessionID: true,
						ValidateUser: true,
					},
					Validate: config.OAuth2Validate{
						Expression: "openvpn.commonName == token.claims.preferred_username",
						Groups:     []string{"test", "test2"},
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
				assert.Equal(t, tc.conf, *conf)
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
	assert.Contains(t, buf.String(), "--config string")
	assert.Contains(t, buf.String(), "(env: OPENVPN_AUTH_OAUTH2_CONFIG_FILE)")
	assert.Contains(t, buf.String(), "(env: OPENVPN_AUTH_OAUTH2_HTTP_LISTEN)")
	assert.Contains(t, buf.String(), "--openvpn.command-timeout duration")
	assert.Contains(t, buf.String(), "(env: OPENVPN_AUTH_OAUTH2_OPENVPN_COMMAND_TIMEOUT)")
	assert.Contains(t, buf.String(), "--openvpn.pass-through.socket-mode value")
	assert.Contains(t, buf.String(), "(default 0660)")
	assert.NotContains(t, buf.String(), "--http.short-url")
	assert.NotContains(t, buf.String(), "--openvpn.common-name.mode")
	assert.NotContains(t, buf.String(), "(env: CONFIG_HTTP_LISTEN)")
}

func TestConfigFileEnvironmentVariable(t *testing.T) {
	var buf bytes.Buffer

	configFile, err := os.CreateTemp(t.TempDir(), "openvpn-auth-oauth2-*")
	require.NoError(t, err)

	_, err = configFile.WriteString("http:\n  listen: \":9100\"\n")
	require.NoError(t, err)
	require.NoError(t, configFile.Close())

	t.Setenv("OPENVPN_AUTH_OAUTH2_CONFIG_FILE", configFile.Name())

	conf, err := config.New([]string{"openvpn-auth-oauth2"}, &buf)
	require.NoError(t, err)
	assert.Equal(t, ":9100", conf.HTTP.Listen)
}

func TestConfigPrecedence(t *testing.T) {
	var buf bytes.Buffer

	configFile, err := os.CreateTemp(t.TempDir(), "openvpn-auth-oauth2-*")
	require.NoError(t, err)

	_, err = configFile.WriteString("openvpn:\n  command-timeout: 11s\n")
	require.NoError(t, err)
	require.NoError(t, configFile.Close())

	t.Setenv("OPENVPN_AUTH_OAUTH2_OPENVPN_COMMAND_TIMEOUT", "12s")

	conf, err := config.New(
		[]string{
			"openvpn-auth-oauth2",
			"--config",
			configFile.Name(),
			"--openvpn.command-timeout=13s",
		},
		&buf,
	)
	require.NoError(t, err)
	assert.Equal(t, 13*time.Second, conf.OpenVPN.CommandTimeout)
}

func TestConfigRejectsRemovedTopLevelConfigProperty(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	configFile, err := os.CreateTemp(t.TempDir(), "openvpn-auth-oauth2-*")
	require.NoError(t, err)

	_, err = configFile.WriteString("config: other.yaml\n")
	require.NoError(t, err)
	require.NoError(t, configFile.Close())

	_, err = config.New([]string{"openvpn-auth-oauth2", "--config", configFile.Name()}, &buf)

	require.Error(t, err)
	require.ErrorContains(t, err, "field config not found")
}

func TestConfigRejectsAmbiguousSocketMode(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		configFile string
		args       []string
	}{
		{
			name:       "yaml",
			configFile: "openvpn:\n  pass-through:\n    socket-mode: 660\n",
		},
		{
			name: "command line",
			args: []string{"--openvpn.pass-through.socket-mode=660"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer

			args := slices.Concat([]string{"openvpn-auth-oauth2"}, tc.args)
			if tc.configFile != "" {
				configFile, err := os.CreateTemp(t.TempDir(), "openvpn-auth-oauth2-*")
				require.NoError(t, err)

				_, err = configFile.WriteString(tc.configFile)
				require.NoError(t, err)
				require.NoError(t, configFile.Close())

				args = append(args, "--config", configFile.Name())
			}

			_, err := config.New(args, &buf)

			require.ErrorContains(t, err, "invalid file mode")
		})
	}
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
				conf.OpenVPN.Bypass.CommonNames = types.RegexpSlice{regexp.MustCompile("^(?:a)$"), regexp.MustCompile("^(?:b)$")}

				return conf
			}(),
		},
		{
			"--oauth2.validate.expression",
			[]string{"--oauth2.validate.expression=openvpn.commonName == token.claims.preferred_username"},
			func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Validate.Expression = "openvpn.commonName == token.claims.preferred_username"

				return conf
			}(),
		},
		{
			"--http.assets-path",
			[]string{"--http.assets-path=."},
			func() config.Config {
				dirFS, err := types.NewFS(".")
				require.NoError(t, err)

				conf := config.Defaults
				conf.HTTP.AssetPath = dirFS

				return conf
			}(),
		},
		{
			"--openvpn.enforce-unique-user",
			[]string{"--openvpn.enforce-unique-user"},
			func() config.Config {
				conf := config.Defaults
				conf.OpenVPN.EnforceUniqueUser = true

				return conf
			}(),
		},
		{
			"--openvpn.command-timeout",
			[]string{"--openvpn.command-timeout=42s"},
			func() config.Config {
				conf := config.Defaults
				conf.OpenVPN.CommandTimeout = 42 * time.Second

				return conf
			}(),
		},
		{
			"--openvpn.pass-through.socket-mode",
			[]string{"--openvpn.pass-through.socket-mode=0640"},
			func() config.Config {
				conf := config.Defaults
				conf.OpenVPN.Passthrough.SocketMode = 0o640

				return conf
			}(),
		},
		{
			"--provider.google.validate.groups-transitive",
			[]string{"--provider.google.validate.groups-transitive"},
			func() config.Config {
				conf := config.Defaults
				conf.Provider.Google.Validate.GroupsTransitive = true

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
			assert.Equal(t, tc.expectConfig, *conf)
		})
	}
}
