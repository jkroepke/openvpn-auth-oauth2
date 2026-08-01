package openvpn //nolint:testpackage

import (
	"io"
	"log/slog"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/openvpn/connection"
)

func BenchmarkHandleClientMessage(b *testing.B) {
	const message = ">CLIENT:CONNECT,0,1\r\n" +
		">CLIENT:ENV,password=secret\r\n" +
		">CLIENT:ENV,common_name=test\r\n" +
		">CLIENT:ENV,END\r\n"

	for _, tc := range []struct {
		name  string
		level slog.Level
	}{
		{name: "debug-disabled", level: slog.LevelInfo},
		{name: "debug-enabled", level: slog.LevelDebug},
	} {
		b.Run(tc.name, func(b *testing.B) {
			conf := config.Defaults
			clientsCh := make(chan connection.Client, 1)
			client := Client{
				conf:      &conf,
				logger:    slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: tc.level})), //nolint:sloglint
				clientsCh: clientsCh,
			}

			var parsedClient connection.Client

			b.ReportAllocs()

			for b.Loop() {
				if err := client.handleClientMessage(b.Context(), message); err != nil {
					b.Fatal(err)
				}

				parsedClient = <-clientsCh
			}

			_ = parsedClient
		})
	}
}
