package types_test

import (
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
)

func BenchmarkURLUnmarshalText(b *testing.B) {
	input := []byte("https://issuer.example.com/oauth2/v2/authorize?audience=vpn&prompt=login")

	var parsedURL types.URL

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		if err := parsedURL.UnmarshalText(input); err != nil {
			b.Fatal(err)
		}
	}

	_ = parsedURL
}

func BenchmarkStringSliceUnmarshalText(b *testing.B) {
	for _, tc := range []struct {
		name  string
		input []byte
	}{
		{
			name:  "short",
			input: []byte("openid,profile,email"),
		},
		{
			name:  "long",
			input: []byte("alpha,beta,gamma,delta,epsilon,zeta,eta,theta,iota,kappa,lambda,mu"),
		},
	} {
		b.Run(tc.name, func(b *testing.B) {
			var stringSlice types.StringSlice

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				if err := stringSlice.UnmarshalText(tc.input); err != nil {
					b.Fatal(err)
				}
			}

			_ = stringSlice
		})
	}
}

func BenchmarkRegexpSliceUnmarshalText(b *testing.B) {
	for _, tc := range []struct {
		name  string
		input []byte
	}{
		{
			name:  "short",
			input: []byte("group1,group2,group3"),
		},
		{
			name:  "anchored-like-patterns",
			input: []byte("client-.*,admin-.*,support-.*"),
		},
	} {
		b.Run(tc.name, func(b *testing.B) {
			var regexpSlice types.RegexpSlice

			b.ReportAllocs()
			b.ResetTimer()

			for b.Loop() {
				if err := regexpSlice.UnmarshalText(tc.input); err != nil {
					b.Fatal(err)
				}
			}

			_ = regexpSlice
		})
	}
}
