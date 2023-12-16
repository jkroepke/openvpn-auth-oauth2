package config_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/pkg/testutils"
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
			"--openvpn.bypass.cn",
			[]string{"--openvpn.bypass.cn=a,b"},
			map[string]any{
				"openvpn.bypass.cn": []string{"a", "b"},
			},
		},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			flagSet := config.FlagSet()
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

func TestValidate(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		conf config.Config
		err  string
	}{
		{"", config.Config{}, "-"},
		{"", config.Config{HTTP: config.HTTP{}}, "-"},
		{"", config.Config{HTTP: config.HTTP{}, OAuth2: config.OAuth2{}}, "-"},
		{"", config.Config{HTTP: config.HTTP{}, OAuth2: config.OAuth2{}, OpenVpn: config.OpenVpn{}}, "-"},
		{"", config.Config{HTTP: config.HTTP{}, OAuth2: config.OAuth2{}, OpenVpn: config.OpenVpn{}, Log: config.Log{}}, "-"},
		{"", config.Config{HTTP: config.HTTP{}, OAuth2: config.OAuth2{Client: config.OAuth2Client{}}, OpenVpn: config.OpenVpn{}, Log: config.Log{}}, "-"},
		{"", config.Config{HTTP: config.HTTP{}, OAuth2: config.OAuth2{Client: config.OAuth2Client{}, Endpoints: config.OAuth2Endpoints{}, Validate: config.OAuth2Validate{}}, OpenVpn: config.OpenVpn{}, Log: config.Log{}}, "-"},
		{"", config.Config{HTTP: config.HTTP{}, OAuth2: config.OAuth2{Client: config.OAuth2Client{}, Endpoints: config.OAuth2Endpoints{}, Validate: config.OAuth2Validate{}}, OpenVpn: config.OpenVpn{Bypass: config.OpenVpnBypass{}}, Log: config.Log{}}, "-"},
		{"", config.Config{HTTP: config.HTTP{BaseURL: &url.URL{}}, OAuth2: config.OAuth2{Client: config.OAuth2Client{}, Endpoints: config.OAuth2Endpoints{}, Validate: config.OAuth2Validate{}}, OpenVpn: config.OpenVpn{Bypass: config.OpenVpnBypass{}}, Log: config.Log{}}, "-"},
		{"", config.Config{HTTP: config.HTTP{BaseURL: &url.URL{Scheme: "http", Host: "invalid"}}, OAuth2: config.OAuth2{Client: config.OAuth2Client{}, Endpoints: config.OAuth2Endpoints{}, Validate: config.OAuth2Validate{}}, OpenVpn: config.OpenVpn{Bypass: config.OpenVpnBypass{}}, Log: config.Log{}}, "-"},
		{"", config.Config{HTTP: config.HTTP{BaseURL: &url.URL{Scheme: "http", Host: "invalid"}, Secret: "invalid"}, OAuth2: config.OAuth2{Issuer: &url.URL{}, Client: config.OAuth2Client{}, Endpoints: config.OAuth2Endpoints{}, Validate: config.OAuth2Validate{}}, OpenVpn: config.OpenVpn{Bypass: config.OpenVpnBypass{}}, Log: config.Log{}}, "-"},
		{"", config.Config{HTTP: config.HTTP{BaseURL: &url.URL{Scheme: "http", Host: "invalid"}, Secret: "invalid"}, OAuth2: config.OAuth2{Issuer: &url.URL{Scheme: "http", Host: "invalid"}, Client: config.OAuth2Client{}, Endpoints: config.OAuth2Endpoints{}, Validate: config.OAuth2Validate{}}, OpenVpn: config.OpenVpn{Bypass: config.OpenVpnBypass{}}, Log: config.Log{}}, "-"},
		{"", config.Config{HTTP: config.HTTP{BaseURL: &url.URL{Scheme: "http", Host: "invalid"}, Secret: "invalid", Check: config.HTTPCheck{}}, OAuth2: config.OAuth2{Issuer: &url.URL{Scheme: "http", Host: "invalid"}, Client: config.OAuth2Client{ID: "client"}, Endpoints: config.OAuth2Endpoints{}, Validate: config.OAuth2Validate{}}, OpenVpn: config.OpenVpn{Bypass: config.OpenVpnBypass{}}, Log: config.Log{}}, "http.secret requires a length of 16, 24 or 32"},
		{"", config.Config{HTTP: config.HTTP{BaseURL: &url.URL{Scheme: "http", Host: "invalid"}, Secret: "invalid", Check: config.HTTPCheck{}}, OAuth2: config.OAuth2{Issuer: &url.URL{Scheme: "http", Host: "invalid"}, Client: config.OAuth2Client{ID: "client"}, Endpoints: config.OAuth2Endpoints{}, Validate: config.OAuth2Validate{}}, OpenVpn: config.OpenVpn{Bypass: config.OpenVpnBypass{}}, Log: config.Log{}}, "http.secret requires a length of 16, 24 or 32"},
		{"", config.Config{HTTP: config.HTTP{BaseURL: &url.URL{Scheme: "http", Host: "invalid"}, Secret: testutils.HTTPSecret, Check: config.HTTPCheck{}}, OAuth2: config.OAuth2{Issuer: &url.URL{Scheme: "http", Host: "invalid"}, Client: config.OAuth2Client{ID: "client"}, Endpoints: config.OAuth2Endpoints{}, Validate: config.OAuth2Validate{}}, OpenVpn: config.OpenVpn{Addr: &url.URL{}, Bypass: config.OpenVpnBypass{}}, Log: config.Log{}}, "openvpn.addr is required"},
		{"", config.Config{HTTP: config.HTTP{BaseURL: &url.URL{Scheme: "http", Host: "invalid"}, Secret: testutils.HTTPSecret, Check: config.HTTPCheck{}}, OAuth2: config.OAuth2{Issuer: &url.URL{Scheme: "http", Host: "invalid"}, Client: config.OAuth2Client{ID: "client"}, Endpoints: config.OAuth2Endpoints{}, Validate: config.OAuth2Validate{}}, OpenVpn: config.OpenVpn{Addr: &url.URL{Scheme: "tcps", Host: "127.0.0.1:9000"}, Bypass: config.OpenVpnBypass{}}, Log: config.Log{}}, "openvpn.addr: invalid URL. only tcp://addr or unix://addr scheme supported"},
		{"", config.Config{HTTP: config.HTTP{BaseURL: &url.URL{Scheme: "httpss", Host: "invalid"}, Secret: testutils.HTTPSecret, Check: config.HTTPCheck{}}, OAuth2: config.OAuth2{Issuer: &url.URL{Scheme: "http", Host: "invalid"}, Client: config.OAuth2Client{ID: "client"}, Endpoints: config.OAuth2Endpoints{}, Validate: config.OAuth2Validate{}}, OpenVpn: config.OpenVpn{Addr: &url.URL{Scheme: "tcp", Host: "127.0.0.1:9000"}, Bypass: config.OpenVpnBypass{}}, Log: config.Log{}}, "-"},
		{"", config.Config{HTTP: config.HTTP{BaseURL: &url.URL{Scheme: "http", Host: "invalid"}, Secret: testutils.HTTPSecret, Check: config.HTTPCheck{}}, OAuth2: config.OAuth2{Issuer: &url.URL{Scheme: "http", Host: "invalid"}, Client: config.OAuth2Client{ID: "client"}, Endpoints: config.OAuth2Endpoints{}, Validate: config.OAuth2Validate{}}, OpenVpn: config.OpenVpn{Addr: &url.URL{Scheme: "tcp", Host: "127.0.0.1:9000"}, Bypass: config.OpenVpnBypass{}}, Log: config.Log{}}, ""},
		{"", config.Config{HTTP: config.HTTP{BaseURL: &url.URL{Scheme: "http", Host: "invalid"}, Secret: testutils.HTTPSecret, Check: config.HTTPCheck{}}, OAuth2: config.OAuth2{Issuer: &url.URL{Scheme: "http", Host: "invalid"}, Client: config.OAuth2Client{ID: "client"}, Endpoints: config.OAuth2Endpoints{Token: &url.URL{Scheme: "http", Host: "invalid"}, Auth: &url.URL{Scheme: "http", Host: "invalid"}}, Validate: config.OAuth2Validate{}}, OpenVpn: config.OpenVpn{Addr: &url.URL{Scheme: "tcp", Host: "127.0.0.1:9000"}, Bypass: config.OpenVpnBypass{}}, Log: config.Log{}}, ""},
	} {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := config.Validate(config.ManagementClient, tt.conf)
			if tt.err == "" {
				require.NoError(t, err)
			} else if tt.err != "-" {
				require.Error(t, err)
				assert.Equal(t, tt.err, err.Error())
			}
		})
	}
}
