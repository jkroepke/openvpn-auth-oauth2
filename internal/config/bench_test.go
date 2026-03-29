package config //nolint:testpackage

import (
	"io"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
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

func BenchmarkLookupEnvOrDefault(b *testing.B) {
	b.Run("string", func(b *testing.B) {
		const key = "benchmark-string"
		b.Setenv(getEnvironmentVariableByFlagName(key), "benchmark-value")

		var actual string

		b.ReportAllocs()
		b.ResetTimer()

		for b.Loop() {
			actual = lookupEnvOrDefault(key, "default-value")
		}

		_ = actual
	})

	b.Run("duration", func(b *testing.B) {
		const key = "benchmark-duration"
		b.Setenv(getEnvironmentVariableByFlagName(key), "5m")

		var actual time.Duration

		b.ReportAllocs()
		b.ResetTimer()

		for b.Loop() {
			actual = lookupEnvOrDefault(key, time.Minute)
		}

		_ = actual
	})

	b.Run("url", func(b *testing.B) {
		const key = "benchmark-url"
		b.Setenv(getEnvironmentVariableByFlagName(key), "http://localhost:9000")

		var actual types.URL

		b.ReportAllocs()
		b.ResetTimer()

		for b.Loop() {
			actual = lookupEnvOrDefault(key, types.URL{})
		}

		_ = actual
	})

	b.Run("string-slice", func(b *testing.B) {
		const key = "benchmark-string-slice"
		b.Setenv(getEnvironmentVariableByFlagName(key), "alpha,beta,gamma,delta")

		var actual types.StringSlice

		b.ReportAllocs()
		b.ResetTimer()

		for b.Loop() {
			actual = lookupEnvOrDefault(key, types.StringSlice{})
		}

		_ = actual
	})
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
