package oauth2 //nolint:testpackage

import (
	"io"
	"log/slog"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/state"
)

func BenchmarkCreateSessionLogger(b *testing.B) {
	// Exercise a real handler that retains attributes; DiscardHandler intentionally drops them.
	client := Client{logger: slog.New(slog.NewTextHandler(io.Discard, nil))} //nolint:sloglint
	session := state.State{
		Client: state.ClientIdentifier{
			CID:        1,
			KID:        2,
			CommonName: "user@example.com",
			SessionID:  "session-id",
		},
		IPAddr:       "192.0.2.1",
		IPPort:       "1194",
		SessionState: "session-state",
	}

	b.Run("common", func(b *testing.B) {
		var logger *slog.Logger

		b.ReportAllocs()

		for b.Loop() {
			logger = client.createSessionLogger(session)
		}

		_ = logger
	})

	b.Run("with-state", func(b *testing.B) {
		var logger *slog.Logger

		b.ReportAllocs()

		for b.Loop() {
			logger = client.createSessionLoggerWithState(session)
		}

		_ = logger
	})
}
