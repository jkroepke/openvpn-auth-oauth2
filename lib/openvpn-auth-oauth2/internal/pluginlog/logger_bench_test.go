//go:build (darwin || linux || openbsd || freebsd) && cgo

package pluginlog_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/lib/openvpn-auth-oauth2/internal/pluginlog"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/lib/openvpn-auth-oauth2/internal/util/testutil"
)

func BenchmarkPluginHandler_Handle(b *testing.B) {
	benchmarkTime := time.Date(2026, time.July, 2, 10, 11, 12, 13, time.UTC)

	for _, tc := range []struct {
		name       string
		message    string
		attributes []slog.Attr
	}{
		{
			name:    "message",
			message: "client connected",
		},
		{
			name:    "attributes",
			message: "client connected",
			attributes: []slog.Attr{
				slog.String("user", "alice"),
				slog.Int("cid", 7),
				slog.Bool("ok", true),
				slog.Duration("wait", 1500*time.Microsecond),
				slog.Time("at", benchmarkTime),
				slog.Group("session", slog.String("id", "sid-1")),
			},
		},
		{
			name:    "max_message",
			message: strings.Repeat("x", 375),
		},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.Run("serial", func(b *testing.B) {
				handler, record := newBenchmarkHandler(tc.message, tc.attributes, benchmarkTime)
				ctx := context.Background()

				b.ReportAllocs()

				for b.Loop() {
					_ = handler.Handle(ctx, record)
				}
			})

			b.Run("parallel", func(b *testing.B) {
				handler, record := newBenchmarkHandler(tc.message, tc.attributes, benchmarkTime)
				ctx := context.Background()

				b.ReportAllocs()
				b.ResetTimer()
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						_ = handler.Handle(ctx, record)
					}
				})
			})
		})
	}
}

func newBenchmarkHandler(message string, attributes []slog.Attr, recordTime time.Time) (slog.Handler, slog.Record) {
	handler := pluginlog.NewOpenVPNPluginLogger(testutil.Callbacks()).WithAttrs([]slog.Attr{
		slog.String("component", "plugin"),
	})

	record := slog.NewRecord(recordTime, slog.LevelInfo, message, 0)
	record.AddAttrs(attributes...)

	return handler, record
}
