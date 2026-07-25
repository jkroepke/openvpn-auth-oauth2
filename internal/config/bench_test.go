package config //nolint:testpackage

import (
	"io"
	"testing"
)

func BenchmarkLookupConfigArgument(b *testing.B) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{
			name: "equals",
			args: []string{"openvpn-auth-oauth2", "--config=/tmp/config.yaml"},
		},
		{
			name: "separate-argument",
			args: []string{"openvpn-auth-oauth2", "--config", "/tmp/config.yaml"},
		},
		{
			name: "missing",
			args: []string{"openvpn-auth-oauth2", "--http.listen=:9001"},
		},
	} {
		b.Run(tc.name, func(b *testing.B) {
			var configFile string

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				configFile = lookupConfigArgument(tc.args)
			}

			_ = configFile
		})
	}
}

func BenchmarkReadFromFlagAndEnvironment(b *testing.B) {
	flagArgs := []string{
		"openvpn-auth-oauth2",
		"--http.listen=:9001",
		"--http.secret=1234567890123456",
		"--oauth2.issuer=http://localhost",
		"--oauth2.endpoint.discovery=http://localhost/.well-known/openid-configuration",
		"--oauth2.endpoint.auth=http://localhost/authorize",
		"--oauth2.endpoint.token=http://localhost/token",
		"--oauth2.client.id=bench-client",
		"--oauth2.client.secret=bench-secret",
		"--oauth2.authorize-params=prompt=login&audience=vpn",
	}

	b.Run("flags", func(b *testing.B) {
		var conf Config

		b.ReportAllocs()
		b.ResetTimer()

		for b.Loop() {
			conf = Defaults
			if err := conf.ReadFromFlagAndEnvironment(flagArgs, io.Discard); err != nil {
				b.Fatal(err)
			}
		}

		_ = conf
	})

	b.Run("environment", func(b *testing.B) {
		b.Setenv(getEnvironmentVariableByFlagName("http.listen"), ":9002")
		b.Setenv(getEnvironmentVariableByFlagName("http.secret"), "1234567890123456")
		b.Setenv(getEnvironmentVariableByFlagName("oauth2.issuer"), "http://localhost")
		b.Setenv(getEnvironmentVariableByFlagName("oauth2.client.id"), "bench-client")
		b.Setenv(getEnvironmentVariableByFlagName("oauth2.client.secret"), "bench-secret")
		b.Setenv(getEnvironmentVariableByFlagName("oauth2.authorize-params"), "prompt=login&audience=vpn")

		var conf Config

		b.ReportAllocs()
		b.ResetTimer()

		for b.Loop() {
			conf = Defaults
			if err := conf.ReadFromFlagAndEnvironment([]string{"openvpn-auth-oauth2"}, io.Discard); err != nil {
				b.Fatal(err)
			}
		}

		_ = conf
	})
}
