package openvpn //nolint:testpackage

import (
	"strings"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/openvpn/connection"
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

func BenchmarkBuildClientPendingAuthCommand(b *testing.B) {
	client := connection.Client{CID: 12345, KID: 67890}
	startURL := "https://vpn.example.com/oauth2/start?state=" + strings.Repeat("a", 256)

	var (
		command string
		err     error
	)

	b.ReportAllocs()

	for b.Loop() {
		command, err = buildClientPendingAuthCommand(client, startURL, 300*time.Second)
	}

	if err != nil {
		b.Fatal(err)
	}

	_ = command
}
