package openvpn //nolint:testpackage

import (
	"io"
	"log/slog"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
)

func BenchmarkManagementCommandName(b *testing.B) {
	const command = "client-pending-auth 123 456 \"WEB_AUTH::https://example.com/oauth2/start\" 300\r\n"

	var name string

	b.ReportAllocs()

	for b.Loop() {
		name = managementCommandName(command)
	}

	if name != "client-pending-auth" {
		b.Fatalf("unexpected command name %q", name)
	}
}

func BenchmarkSendCommand(b *testing.B) {
	conf := config.Defaults
	client := New(slog.New(slog.NewTextHandler(io.Discard, nil)), &conf) //nolint:sloglint
	doneCh := make(chan struct{})

	go func() {
		defer close(doneCh)

		for range client.commandsCh {
			client.commandResponseCh <- "SUCCESS: command succeeded"
		}
	}()

	b.Cleanup(func() {
		client.Shutdown(b.Context())
		<-doneCh
	})

	b.ReportAllocs()

	for b.Loop() {
		if _, err := client.SendCommand(b.Context(), "status 3", false); err != nil {
			b.Fatal(err)
		}
	}
}
