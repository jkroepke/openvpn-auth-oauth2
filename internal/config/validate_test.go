package config_test

import (
	"net/url"
	"testing"
	"text/template"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidate(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		conf config.Config
		err  string
	}{
		{
			config.Config{},
			"oauth2.issuer is required",
		},
		{
			config.Config{
				OAuth2: config.OAuth2{
					Issuer: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
				},
			},
			"oauth2.client.id is required",
		},
		{
			config.Config{
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testutils.Secret},
					Issuer: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
				},
			},
			"http.secret is required",
		},
		{
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  types.URL{},
					Secret:   testutils.Secret,
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
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  types.URL{},
					Secret:   testutils.Secret,
					Template: config.Defaults.HTTP.Template,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testutils.Secret},
					Issuer: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
				},
			},
			"http.baseurl is required",
		},
		{
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Secret:   testutils.Secret,
					Template: types.Template{Template: template.Must(template.New("index.gohtml").Parse("{{ slice .invalid.error 1 2 }}"))},
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testutils.Secret},
					Issuer: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
				},
				OpenVPN: config.OpenVPN{
					Addr: types.URL{URL: &url.URL{Scheme: "tcp", Host: "127.0.0.1:9000"}},
				},
			},
			"invalid rendering http.template: template: index.gohtml:1:3: executing \"index.gohtml\" at <slice .invalid.error 1 2>: error calling slice: slice of untyped nil",
		},
		{
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Secret:   testutils.Secret,
					Template: config.Defaults.HTTP.Template,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testutils.Secret},
					Issuer: types.URL{},
				},
			},
			"oauth2.issuer is required",
		},
		{
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Secret:   testutils.Secret,
					Template: config.Defaults.HTTP.Template,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testutils.Secret},
					Issuer: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
				},
			},
			"openvpn.addr is required",
		},
		{
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Secret:   "invalid",
					Template: config.Defaults.HTTP.Template,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testutils.Secret},
					Issuer: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
				},
				OpenVPN: config.OpenVPN{
					Addr: types.URL{URL: &url.URL{Scheme: "tcp", Host: "127.0.0.1:9000"}},
				},
			},
			"http.secret requires a length of 16, 24 or 32",
		},
		{
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  types.URL{URL: &url.URL{Scheme: "invalid", Host: "localhost"}},
					Secret:   testutils.Secret,
					Template: config.Defaults.HTTP.Template,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testutils.Secret},
					Issuer: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
				},
				OpenVPN: config.OpenVPN{
					Addr: types.URL{URL: &url.URL{Scheme: "tcp", Host: "127.0.0.1:9000"}},
				},
			},
			"http.baseurl: invalid URL. only http:// or https:// scheme supported",
		},
		{
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Secret:   testutils.Secret,
					Template: config.Defaults.HTTP.Template,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testutils.Secret},
					Issuer: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
				},
				OpenVPN: config.OpenVPN{
					Addr: types.URL{URL: &url.URL{Scheme: "quic", Host: "127.0.0.1:9000"}},
				},
			},
			"openvpn.addr: invalid URL. only tcp://addr or unix://addr scheme supported",
		},
		{
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Secret:   testutils.Secret,
					Template: config.Defaults.HTTP.Template,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testutils.Secret},
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
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Secret:   testutils.Secret,
					Template: config.Defaults.HTTP.Template,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testutils.Secret},
					Issuer: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Refresh: config.OAuth2Refresh{
						Enabled: true,
						Secret:  testutils.Secret,
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
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Secret:   testutils.Secret,
					Template: config.Defaults.HTTP.Template,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testutils.Secret},
					Issuer: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Refresh: config.OAuth2Refresh{
						Enabled: true,
						Secret:  testutils.Secret,
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
		// common-name-email-regexp validation tests
		{
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Secret:   testutils.Secret,
					Template: config.Defaults.HTTP.Template,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testutils.Secret},
					Issuer: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Validate: config.OAuth2Validate{
						CommonName: "sub",
						CommonNameEmailRegexp: &config.CommonNameEmailRegexp{
							Pattern:     "^([^-]+)",
							Replacement: "$1@example.com",
						},
					},
				},
				OpenVPN: config.OpenVPN{
					Addr: types.URL{URL: &url.URL{Scheme: "tcp", Host: "127.0.0.1:9000"}},
				},
			},
			"oauth2.validate.common-name-email-regexp requires oauth2.validate.common-name to be 'email'",
		},
		{
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Secret:   testutils.Secret,
					Template: config.Defaults.HTTP.Template,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testutils.Secret},
					Issuer: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Validate: config.OAuth2Validate{
						CommonName: "email",
						CommonNameEmailRegexp: &config.CommonNameEmailRegexp{
							Pattern:     "",
							Replacement: "$1@example.com",
						},
					},
				},
				OpenVPN: config.OpenVPN{
					Addr: types.URL{URL: &url.URL{Scheme: "tcp", Host: "127.0.0.1:9000"}},
				},
			},
			"oauth2.validate.common-name-email-regexp.pattern is required",
		},
		{
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Secret:   testutils.Secret,
					Template: config.Defaults.HTTP.Template,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testutils.Secret},
					Issuer: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Validate: config.OAuth2Validate{
						CommonName: "email",
						CommonNameEmailRegexp: &config.CommonNameEmailRegexp{
							Pattern:     "[invalid",
							Replacement: "$1@example.com",
						},
					},
				},
				OpenVPN: config.OpenVPN{
					Addr: types.URL{URL: &url.URL{Scheme: "tcp", Host: "127.0.0.1:9000"}},
				},
			},
			"-", // error message varies by Go version, just check that it fails
		},
		{
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Secret:   testutils.Secret,
					Template: config.Defaults.HTTP.Template,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testutils.Secret},
					Issuer: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Validate: config.OAuth2Validate{
						CommonName: "email",
						CommonNameEmailRegexp: &config.CommonNameEmailRegexp{
							Pattern:     "^([^-]+)",
							Replacement: "",
						},
					},
				},
				OpenVPN: config.OpenVPN{
					Addr: types.URL{URL: &url.URL{Scheme: "tcp", Host: "127.0.0.1:9000"}},
				},
			},
			"oauth2.validate.common-name-email-regexp.replacement is required",
		},
		{
			config.Config{
				HTTP: config.HTTP{
					BaseURL:  types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Secret:   testutils.Secret,
					Template: config.Defaults.HTTP.Template,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testutils.Secret},
					Issuer: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Validate: config.OAuth2Validate{
						CommonName: "email",
						CommonNameEmailRegexp: &config.CommonNameEmailRegexp{
							Pattern:     "^([^-]+)",
							Replacement: "$1@example.com",
						},
					},
				},
				OpenVPN: config.OpenVPN{
					Addr: types.URL{URL: &url.URL{Scheme: "tcp", Host: "127.0.0.1:9000"}},
				},
			},
			"",
		},
	} {
		t.Run(tc.err, func(t *testing.T) {
			t.Parallel()

			err := config.Validate(config.ManagementClient, tc.conf)
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
