package config_test

import (
	"bytes"
	"flag"
	"io"
	"strings"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlagSet(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name       string
		args       []string
		expectArgs map[string]any
	}{
		{
			"--version",
			[]string{"--version"},
			map[string]any{
				"version": true,
			},
		},
		{
			"--openvpn.bypass.common-names",
			[]string{"--openvpn.bypass.common-names=a,b"},
			map[string]any{
				"openvpn.bypass.common-names": []string{"a", "b"},
			},
		},
		{
			"--oauth2.validate.common-name",
			[]string{"--oauth2.validate.common-name=plain"},
			map[string]any{
				"oauth2.validate.common-name": config.Plugin,
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			_ = io.Writer(&buf)

			flagSet := config.FlagSet("")
			flagSet.SetOutput(&buf)
			err := flagSet.Parse(tt.args)
			require.NoError(t, err)

			for arg, expected := range tt.expectArgs {
				switch expectedTyped := expected.(type) {
				case string:
					value := flagSet.Lookup(arg).Value.String()
					assert.Equal(t, expectedTyped, value)
				case bool:
					value := flagSet.Lookup(arg).Value.String() == "true"
					assert.Equal(t, expectedTyped, value)
				case []string:
					value := strings.Split(flagSet.Lookup(arg).Value.String(), ",")
					assert.Equal(t, expectedTyped, value)
				}
			}
		})
	}
}

func TestFlagSetHelp(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	_ = io.Writer(&buf)

	flagSet := config.FlagSet("")
	flagSet.SetOutput(&buf)

	err := flagSet.Parse([]string{"--help"})

	require.ErrorIs(t, flag.ErrHelp, err)
}

func TestValidate(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
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
					Issuer: &config.URL{Scheme: "http", Host: "localhost"},
				},
			},
			"oauth2.client.id is required",
		},
		{
			config.Config{
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testutils.Secret},
					Issuer: &config.URL{Scheme: "http", Host: "localhost"},
				},
			},
			"http.secret is required",
		},
		{
			config.Config{
				HTTP: config.HTTP{
					BaseURL:          &config.URL{},
					Secret:           testutils.Secret,
					CallbackTemplate: config.Defaults.HTTP.CallbackTemplate,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID"},
					Issuer: &config.URL{Scheme: "http", Host: "localhost"},
				},
			},
			"one of oauth2.client.private-key or oauth2.client.secret is required",
		},
		{
			config.Config{
				HTTP: config.HTTP{
					BaseURL:          &config.URL{},
					Secret:           testutils.Secret,
					CallbackTemplate: config.Defaults.HTTP.CallbackTemplate,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testutils.Secret},
					Issuer: &config.URL{Scheme: "http", Host: "localhost"},
				},
			},
			"http.baseurl is required",
		},
		{
			config.Config{
				HTTP: config.HTTP{
					BaseURL:          &config.URL{Scheme: "http", Host: "localhost"},
					Secret:           testutils.Secret,
					CallbackTemplate: config.Defaults.HTTP.CallbackTemplate,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testutils.Secret},
					Issuer: &config.URL{},
				},
			},
			"oauth2.issuer is required",
		},
		{
			config.Config{
				HTTP: config.HTTP{
					BaseURL:          &config.URL{Scheme: "http", Host: "localhost"},
					Secret:           testutils.Secret,
					CallbackTemplate: config.Defaults.HTTP.CallbackTemplate,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testutils.Secret},
					Issuer: &config.URL{Scheme: "http", Host: "localhost"},
				},
			},
			"openvpn.addr is required",
		},
		{
			config.Config{
				HTTP: config.HTTP{
					BaseURL:          &config.URL{Scheme: "http", Host: "localhost"},
					Secret:           "invalid",
					CallbackTemplate: config.Defaults.HTTP.CallbackTemplate,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testutils.Secret},
					Issuer: &config.URL{Scheme: "http", Host: "localhost"},
				},
				OpenVpn: config.OpenVpn{
					Addr: &config.URL{Scheme: "tcp", Host: "127.0.0.1:9000"},
				},
			},
			"http.secret requires a length of 16, 24 or 32",
		},
		{
			config.Config{
				HTTP: config.HTTP{
					BaseURL:          &config.URL{Scheme: "invalid", Host: "localhost"},
					Secret:           testutils.Secret,
					CallbackTemplate: config.Defaults.HTTP.CallbackTemplate,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testutils.Secret},
					Issuer: &config.URL{Scheme: "http", Host: "localhost"},
				},
				OpenVpn: config.OpenVpn{
					Addr: &config.URL{Scheme: "tcp", Host: "127.0.0.1:9000"},
				},
			},
			"http.baseurl: invalid URL. only http:// or https:// scheme supported",
		},
		{
			config.Config{
				HTTP: config.HTTP{
					BaseURL:          &config.URL{Scheme: "http", Host: "localhost"},
					Secret:           testutils.Secret,
					CallbackTemplate: config.Defaults.HTTP.CallbackTemplate,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testutils.Secret},
					Issuer: &config.URL{Scheme: "http", Host: "localhost"},
				},
				OpenVpn: config.OpenVpn{
					Addr: &config.URL{Scheme: "quic", Host: "127.0.0.1:9000"},
				},
			},
			"openvpn.addr: invalid URL. only tcp://addr or unix://addr scheme supported",
		},
		{
			config.Config{
				HTTP: config.HTTP{
					BaseURL:          &config.URL{Scheme: "http", Host: "localhost"},
					Secret:           testutils.Secret,
					CallbackTemplate: config.Defaults.HTTP.CallbackTemplate,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testutils.Secret},
					Issuer: &config.URL{Scheme: "http", Host: "localhost"},
					Refresh: config.OAuth2Refresh{
						Enabled: true,
					},
				},
				OpenVpn: config.OpenVpn{
					Addr: &config.URL{Scheme: "tcp", Host: "127.0.0.1:9000"},
				},
			},
			"oauth2.refresh.secret requires a length of 16, 24 or 32",
		},
		{
			config.Config{
				HTTP: config.HTTP{
					BaseURL:          &config.URL{Scheme: "http", Host: "localhost"},
					Secret:           testutils.Secret,
					CallbackTemplate: config.Defaults.HTTP.CallbackTemplate,
				},
				OAuth2: config.OAuth2{
					Client: config.OAuth2Client{ID: "ID", Secret: testutils.Secret},
					Issuer: &config.URL{Scheme: "http", Host: "localhost"},
					Refresh: config.OAuth2Refresh{
						Enabled: true,
						Secret:  testutils.Secret,
					},
					Endpoints: config.OAuth2Endpoints{
						Discovery: &config.URL{Scheme: "http", Host: "localhost"},
					},
				},
				OpenVpn: config.OpenVpn{
					Addr: &config.URL{Scheme: "tcp", Host: "127.0.0.1:9000"},
				},
			},
			"",
		},
	} {
		t.Run(tt.err, func(t *testing.T) {
			t.Parallel()

			err := config.Validate(config.ManagementClient, tt.conf)
			if tt.err == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)

				if tt.err != "-" {
					assert.EqualError(t, err, tt.err)
				}
			}
		})
	}
}
