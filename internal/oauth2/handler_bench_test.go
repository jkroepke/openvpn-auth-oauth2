package oauth2 //nolint:testpackage

import (
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/state"
)

type benchmarkResponseWriter struct{}

func (benchmarkResponseWriter) Header() http.Header {
	return nil
}

func (benchmarkResponseWriter) Write(body []byte) (int, error) {
	return len(body), nil
}

func (benchmarkResponseWriter) WriteHeader(_ int) {}

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

func BenchmarkWithIDTokenClaimsLogger(b *testing.B) {
	// Exercise a real handler that retains attributes while keeping the debug record disabled.
	logger := slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError})) //nolint:sloglint
	claims := &idtoken.Claims{
		Claims:            map[string]any{"sub": "subject"},
		EMail:             "user@example.com",
		PreferredUsername: "user",
	}
	claims.Subject = "subject"
	tokens := &idtoken.IDToken{IDTokenClaims: claims}

	var loggerWithClaims *slog.Logger

	b.ReportAllocs()

	for b.Loop() {
		loggerWithClaims = withIDTokenClaimsLogger(logger, tokens)
	}

	_ = loggerWithClaims
}

func BenchmarkWithUserLogger(b *testing.B) {
	// Exercise a real handler that retains attributes; DiscardHandler intentionally drops them.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint

	var loggerWithUser *slog.Logger

	b.ReportAllocs()

	for b.Loop() {
		loggerWithUser = withUserLogger(logger, "subject", "user")
	}

	_ = loggerWithUser
}

func BenchmarkWriteHTTPError(b *testing.B) {
	conf := config.Defaults
	client := Client{conf: &conf}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil)) //nolint:sloglint
	ctx := b.Context()
	w := benchmarkResponseWriter{}

	b.ReportAllocs()

	for b.Loop() {
		client.writeHTTPError(ctx, w, logger, http.StatusBadRequest, "Bad Request", "state is empty")
	}
}
