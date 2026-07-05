package config_test

import (
	"html/template"
	"net/url"
	"testing"
	"testing/fstest"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/test/testsuite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidate(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		conf config.Config
		err  string
	}{
		{
			"missing oauth2 issuer",
			config.Config{},
			"oauth2.issuer is required",
		},
		{
			"missing oauth2 client id",
			config.Config{
				OAuth2: config.OAuth2{
					Issuer: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
				},
			},
			"oauth2.client.id is required",
		},
		{
			"missing http secret",
			config.Config{
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testsuite.Secret},
					Issuer: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
				},
			},
			"http.secret is required",
		},
		{
			"missing oauth2 client private key and secret",
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  types.URL{},
					Secret:   testsuite.Secret,
					Template: config.Defaults.HTTP.Template,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID"},
					Issuer: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
				},
			},
			"one of oauth2.client.private-key or oauth2.client.secret is required",
		},
		{
			"missing http base url",
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  types.URL{},
					Secret:   testsuite.Secret,
					Template: config.Defaults.HTTP.Template,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testsuite.Secret},
					Issuer: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
				},
			},
			"http.baseurl is required",
		},
		{
			"invalid http template rendering",
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Secret:   testsuite.Secret,
					Template: types.Template{Template: template.Must(template.New("index.gohtml").Parse("{{ slice .invalid.error 1 2 }}"))},
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testsuite.Secret},
					Issuer: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
				},
				OpenVPN: config.OpenVPN{
					Addr: types.URL{URL: &url.URL{Scheme: "tcp", Host: "127.0.0.1:9000"}},
				},
			},
			"invalid rendering http.template: template: index.gohtml:1:3: executing \"index.gohtml\" at <slice .invalid.error 1 2>: error calling slice: slice of untyped nil",
		},
		{
			"missing oauth2 issuer after http configured",
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Secret:   testsuite.Secret,
					Template: config.Defaults.HTTP.Template,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testsuite.Secret},
					Issuer: types.URL{},
				},
			},
			"oauth2.issuer is required",
		},
		{
			"missing openvpn address",
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Secret:   testsuite.Secret,
					Template: config.Defaults.HTTP.Template,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testsuite.Secret},
					Issuer: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
				},
			},
			"openvpn.addr is required",
		},
		{
			"invalid http secret length",
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Secret:   "invalid",
					Template: config.Defaults.HTTP.Template,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testsuite.Secret},
					Issuer: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
				},
				OpenVPN: config.OpenVPN{
					Addr: types.URL{URL: &url.URL{Scheme: "tcp", Host: "127.0.0.1:9000"}},
				},
			},
			"http.secret requires a length of 16, 24 or 32",
		},
		{
			"invalid http base url scheme",
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  types.URL{URL: &url.URL{Scheme: "invalid", Host: "localhost"}},
					Secret:   testsuite.Secret,
					Template: config.Defaults.HTTP.Template,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testsuite.Secret},
					Issuer: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
				},
				OpenVPN: config.OpenVPN{
					Addr: types.URL{URL: &url.URL{Scheme: "tcp", Host: "127.0.0.1:9000"}},
				},
			},
			"http.baseurl: invalid URL. only http:// or https:// scheme supported",
		},
		{
			"invalid openvpn address scheme",
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Secret:   testsuite.Secret,
					Template: config.Defaults.HTTP.Template,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testsuite.Secret},
					Issuer: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
				},
				OpenVPN: config.OpenVPN{
					Addr: types.URL{URL: &url.URL{Scheme: "quic", Host: "127.0.0.1:9000"}},
				},
			},
			"openvpn.addr: invalid URL. only tcp://addr or unix://addr scheme supported",
		},
		{
			"invalid oauth2 refresh secret length",
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Secret:   testsuite.Secret,
					Template: config.Defaults.HTTP.Template,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testsuite.Secret},
					Issuer: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Refresh: config.OAuth2Refresh{
						Enabled: true,
					},
				},
				OpenVPN: config.OpenVPN{
					Addr: types.URL{URL: &url.URL{Scheme: "tcp", Host: "127.0.0.1:9000"}},
				},
			},
			"oauth2.refresh.secret requires a length of 16, 24 or 32",
		},
		{
			"missing trusted proxies with proxy headers enabled",
			func() config.Config {
				conf := validConfig()
				conf.HTTP.EnableProxyHeaders = true

				return conf
			}(),
			"http.trusted-proxies is required when http.enable-proxy-headers is true",
		},
		{
			"invalid trusted proxy cidr",
			func() config.Config {
				conf := validConfig()
				conf.HTTP.EnableProxyHeaders = true
				conf.HTTP.TrustedProxies = types.StringSlice{"127.0.0.1"}

				return conf
			}(),
			`http.trusted-proxies: invalid CIDR "127.0.0.1": netip.ParsePrefix("127.0.0.1"): no '/'`,
		},
		{
			"valid trusted proxies",
			func() config.Config {
				conf := validConfig()
				conf.HTTP.EnableProxyHeaders = true
				conf.HTTP.TrustedProxies = types.StringSlice{"127.0.0.1/32", "2001:db8::/64"}

				return conf
			}(),
			"",
		},
		{
			"valid refresh discovery endpoint",
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Secret:   testsuite.Secret,
					Template: config.Defaults.HTTP.Template,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testsuite.Secret},
					Issuer: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Refresh: config.OAuth2Refresh{
						Enabled: true,
						Secret:  testsuite.Secret,
					},
					Endpoints: config.OAuth2Endpoints{
						Discovery: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					},
				},
				OpenVPN: config.OpenVPN{
					Addr: types.URL{URL: &url.URL{Scheme: "tcp", Host: "127.0.0.1:9000"}},
				},
			},
			"",
		},
		{
			"userinfo conflicts with auth and token endpoints",
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Secret:   testsuite.Secret,
					Template: config.Defaults.HTTP.Template,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testsuite.Secret},
					Issuer: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Refresh: config.OAuth2Refresh{
						Enabled: true,
						Secret:  testsuite.Secret,
					},
					UserInfo: true,
					Endpoints: config.OAuth2Endpoints{
						Discovery: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
						Auth:      types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
						Token:     types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					},
				},
				OpenVPN: config.OpenVPN{
					Addr: types.URL{URL: &url.URL{Scheme: "tcp", Host: "127.0.0.1:9000"}},
				},
			},
			"oauth2.userinfo: cannot be used if oauth2.endpoint.auth and oauth2.endpoint.token is set",
		},
		{
			"missing client config expression",
			func() config.Config {
				conf := validConfig()
				conf.OpenVPN.ClientConfig.Enabled = true
				conf.OpenVPN.ClientConfig.Path = types.FS{FS: fstest.MapFS{}}

				return conf
			}(),
			"openvpn.client-config.expression is required when openvpn.client-config.enabled is true",
		},
		{
			"valid client config with omitted common name",
			func() config.Config {
				conf := validConfig()
				conf.OpenVPN.CommonName.Mode = config.CommonNameModeOmit
				conf.OpenVPN.ClientConfig.Enabled = true
				conf.OpenVPN.ClientConfig.Path = types.FS{FS: fstest.MapFS{}}
				conf.OpenVPN.ClientConfig.Expression = `["base"]`

				return conf
			}(),
			"",
		},
		{
			"valid openvpn passthrough",
			func() config.Config {
				conf := validConfig()
				conf.OpenVPN.Passthrough.Enabled = true

				return conf
			}(),
			"",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := config.Validate(config.ManagementClient, &tc.conf)
			if tc.err == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)

				if tc.err != "-" {
					assert.EqualError(t, err, tc.err)
				}
			}
		})
	}
}

func validConfig() config.Config {
	return config.Config{
		HTTP: config.HTTP{
			BaseURL:  types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
			Secret:   testsuite.Secret,
			Template: config.Defaults.HTTP.Template,
		},
		OAuth2: config.OAuth2{
			Client: config.OAuth2Client{ID: "ID", Secret: testsuite.Secret},
			Issuer: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
		},
		OpenVPN: config.OpenVPN{
			Addr: types.URL{URL: &url.URL{Scheme: "tcp", Host: "127.0.0.1:9000"}},
		},
	}
}
