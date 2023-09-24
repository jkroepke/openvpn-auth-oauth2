package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFlagSet(t *testing.T) {
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
		t.Run(tt.name, func(t *testing.T) {
			flagSet := FlagSet()
			err := flagSet.Parse(append([]string{"openvpn-auth-oauth2"}, tt.args...))
			assert.NoError(t, err)
			for arg, expected := range tt.expectArgs {
				switch expectedTyped := expected.(type) {
				case string:
					value, err := flagSet.GetString(arg)
					assert.NoError(t, err)
					assert.Equal(t, expectedTyped, value)
				case bool:
					value, err := flagSet.GetBool(arg)
					assert.NoError(t, err)
					assert.Equal(t, expectedTyped, value)
				case []string:
					value, err := flagSet.GetStringSlice(arg)
					assert.NoError(t, err)
					assert.Equal(t, expectedTyped, value)
				}
			}
		})

	}
}
func TestValidate(t *testing.T) {
	for _, tt := range []struct {
		name   string
		config *Config
		err    string
	}{
		{"", &Config{}, "-"},
		{"", &Config{Http: &Http{}}, "-"},
		{"", &Config{Http: &Http{}, Oauth2: &OAuth2{}}, "-"},
		{"", &Config{Http: &Http{}, Oauth2: &OAuth2{}, OpenVpn: &OpenVpn{}}, "-"},
		{"", &Config{Http: &Http{}, Oauth2: &OAuth2{}, OpenVpn: &OpenVpn{}, Log: &Log{}}, "-"},
		{"", &Config{Http: &Http{}, Oauth2: &OAuth2{Client: &OAuth2Client{}}, OpenVpn: &OpenVpn{}, Log: &Log{}}, "-"},
		{"", &Config{Http: &Http{}, Oauth2: &OAuth2{Client: &OAuth2Client{}, Endpoints: &OAuth2Endpoints{}, Validate: &OAuth2Validate{}}, OpenVpn: &OpenVpn{}, Log: &Log{}}, "-"},
		{"", &Config{Http: &Http{}, Oauth2: &OAuth2{Client: &OAuth2Client{}, Endpoints: &OAuth2Endpoints{}, Validate: &OAuth2Validate{}}, OpenVpn: &OpenVpn{Bypass: &OpenVpnBypass{}}, Log: &Log{}}, "-"},
		{"", &Config{Http: &Http{BaseUrl: "invalid"}, Oauth2: &OAuth2{Client: &OAuth2Client{}, Endpoints: &OAuth2Endpoints{}, Validate: &OAuth2Validate{}}, OpenVpn: &OpenVpn{Bypass: &OpenVpnBypass{}}, Log: &Log{}}, "-"},
		{"", &Config{Http: &Http{BaseUrl: "invalid", Secret: "invalid"}, Oauth2: &OAuth2{Issuer: "invalid", Client: &OAuth2Client{}, Endpoints: &OAuth2Endpoints{}, Validate: &OAuth2Validate{}}, OpenVpn: &OpenVpn{Bypass: &OpenVpnBypass{}}, Log: &Log{}}, "-"},
		{"", &Config{Http: &Http{BaseUrl: "invalid", Secret: "invalid"}, Oauth2: &OAuth2{Issuer: "invalid", Client: &OAuth2Client{Id: "client"}, Endpoints: &OAuth2Endpoints{}, Validate: &OAuth2Validate{}}, OpenVpn: &OpenVpn{Bypass: &OpenVpnBypass{}}, Log: &Log{}}, "http.secret requires a length of 16, 24 or 32"},
		{"", &Config{Http: &Http{BaseUrl: "invalid", Secret: "0123456789101112"}, Oauth2: &OAuth2{Issuer: "invalid", Client: &OAuth2Client{Id: "client"}, Endpoints: &OAuth2Endpoints{}, Validate: &OAuth2Validate{}}, OpenVpn: &OpenVpn{Bypass: &OpenVpnBypass{}}, Log: &Log{}}, "openvpn.addr: invalid URL. only tcp://addr or unix://addr scheme supported"},
		{"", &Config{Http: &Http{BaseUrl: "http://invalid", Secret: "0123456789101112"}, Oauth2: &OAuth2{Issuer: "invalid", Client: &OAuth2Client{Id: "client"}, Endpoints: &OAuth2Endpoints{}, Validate: &OAuth2Validate{}}, OpenVpn: &OpenVpn{Addr: "://-", Bypass: &OpenVpnBypass{}}, Log: &Log{}}, "openvpn.addr: invalid URL. error: parse \"://-\": missing protocol scheme"},
		{"", &Config{Http: &Http{BaseUrl: "http://invalid", Secret: "0123456789101112"}, Oauth2: &OAuth2{Issuer: "invalid", Client: &OAuth2Client{Id: "client"}, Endpoints: &OAuth2Endpoints{}, Validate: &OAuth2Validate{}}, OpenVpn: &OpenVpn{Addr: "tcp://127.0.0.1:9000", Bypass: &OpenVpnBypass{}}, Log: &Log{}}, "-"},
		{"", &Config{Http: &Http{BaseUrl: "://-", Secret: "0123456789101112"}, Oauth2: &OAuth2{Issuer: "http://invalid", Client: &OAuth2Client{Id: "client"}, Endpoints: &OAuth2Endpoints{}, Validate: &OAuth2Validate{}}, OpenVpn: &OpenVpn{Addr: "tcp://127.0.0.1:9000", Bypass: &OpenVpnBypass{}}, Log: &Log{}}, "-"},
		{"", &Config{Http: &Http{BaseUrl: "http://invalid", Secret: "0123456789101112"}, Oauth2: &OAuth2{Issuer: "http://invalid", Client: &OAuth2Client{Id: "client"}, Endpoints: &OAuth2Endpoints{}, Validate: &OAuth2Validate{}}, OpenVpn: &OpenVpn{Addr: "tcp://127.0.0.1:9000", Bypass: &OpenVpnBypass{}}, Log: &Log{}}, ""},
		{"", &Config{Http: &Http{BaseUrl: "http://invalid", Secret: "0123456789101112"}, Oauth2: &OAuth2{Issuer: "http://invalid", Client: &OAuth2Client{Id: "client"}, Endpoints: &OAuth2Endpoints{Token: "://-"}, Validate: &OAuth2Validate{}}, OpenVpn: &OpenVpn{Addr: "tcp://127.0.0.1:9000", Bypass: &OpenVpnBypass{}}, Log: &Log{}}, "oauth2.endpoint.token: invalid URL. error: parse \"://-\": missing protocol scheme"},
		{"", &Config{Http: &Http{BaseUrl: "http://invalid", Secret: "0123456789101112"}, Oauth2: &OAuth2{Issuer: "http://invalid", Client: &OAuth2Client{Id: "client"}, Endpoints: &OAuth2Endpoints{Token: "http://invalid"}, Validate: &OAuth2Validate{}}, OpenVpn: &OpenVpn{Addr: "tcp://127.0.0.1:9000", Bypass: &OpenVpnBypass{}}, Log: &Log{}}, "both oauth2.endpoints.tokenUrl and oauth2.endpoints.authUrl are required"},
		{"", &Config{Http: &Http{BaseUrl: "http://invalid", Secret: "0123456789101112"}, Oauth2: &OAuth2{Issuer: "http://invalid", Client: &OAuth2Client{Id: "client"}, Endpoints: &OAuth2Endpoints{Token: "http://invalid", Auth: "http://invalid"}, Validate: &OAuth2Validate{}}, OpenVpn: &OpenVpn{Addr: "tcp://127.0.0.1:9000", Bypass: &OpenVpnBypass{}}, Log: &Log{}}, ""},
		{"", &Config{Http: &Http{BaseUrl: "http://invalid", Secret: "0123456789101112", CallbackTemplatePath: "nonexists"}, Oauth2: &OAuth2{Issuer: "http://invalid", Client: &OAuth2Client{Id: "client"}, Endpoints: &OAuth2Endpoints{Token: "http://invalid", Auth: "http://invalid"}, Validate: &OAuth2Validate{}}, OpenVpn: &OpenVpn{Addr: "tcp://127.0.0.1:9000", Bypass: &OpenVpnBypass{}}, Log: &Log{}}, "http.callbackTemplatePath: invalid template: open nonexists: no such file or directory"},
		{"", &Config{Http: &Http{BaseUrl: "http://invalid", Secret: "0123456789101112", CallbackTemplatePath: "/dev/null"}, Oauth2: &OAuth2{Issuer: "http://invalid", Client: &OAuth2Client{Id: "client"}, Endpoints: &OAuth2Endpoints{Token: "http://invalid", Auth: "http://invalid"}, Validate: &OAuth2Validate{}}, OpenVpn: &OpenVpn{Addr: "tcp://127.0.0.1:9000", Bypass: &OpenVpnBypass{}}, Log: &Log{}}, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.config)
			if tt.err == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)

				if tt.err != "-" {
					assert.Equal(t, err.Error(), tt.err)
				}
			}
		})
	}
}
