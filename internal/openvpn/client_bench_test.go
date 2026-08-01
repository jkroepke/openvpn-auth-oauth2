package openvpn //nolint:testpackage

import (
	"strings"
	"testing"
)

func BenchmarkBuildOAuth2StartURL(b *testing.B) {
	encryptedOIDCState := strings.Repeat("a", 256)

	var startURL string

	b.ReportAllocs()

	for b.Loop() {
		startURL = buildOAuth2StartURL("https://vpn.example.com/", encryptedOIDCState)
	}

	_ = startURL
}
