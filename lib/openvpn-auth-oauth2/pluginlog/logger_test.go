//go:build (darwin || linux || openbsd || freebsd) && cgo

//nolint:testpackage
package pluginlog

import (
	"log/slog"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/c"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/util/testutil"
	"github.com/stretchr/testify/require"
)

func TestPluginHandler_Handle(t *testing.T) {
	t.Parallel()

	handler := NewOpenVPNPluginLogger(testutil.Callbacks()).WithAttrs([]slog.Attr{
		slog.String("component", "plugin"),
	})

	record := slog.NewRecord(time.Date(2026, time.July, 2, 10, 11, 12, 13, time.UTC), slog.LevelInfo, "client connected", 0)
	record.AddAttrs(
		slog.String("user", "alice"),
		slog.Int("cid", 7),
		slog.Bool("ok", true),
		slog.Duration("wait", 1500*time.Microsecond),
		slog.Time("at", time.Date(2026, time.July, 2, 10, 11, 12, 13, time.UTC)),
		slog.Group("session", slog.String("id", "sid-1")),
	)

	require.NoError(t, handler.Handle(t.Context(), record))
}

func TestPluginHandler_WithAttrs(t *testing.T) {
	t.Parallel()

	handler := NewOpenVPNPluginLogger(testutil.Callbacks())
	child := handler.WithAttrs([]slog.Attr{slog.String("scope", "child")})

	require.Empty(t, handler.preformatted)

	childHandler, ok := child.(*PluginHandler)
	require.True(t, ok)
	require.Equal(t, ` scope="child"`, string(childHandler.preformatted))
}

func TestPluginHandler_WithAttrsEmpty(t *testing.T) {
	t.Parallel()

	handler := NewOpenVPNPluginLogger(testutil.Callbacks())

	require.Same(t, handler, handler.WithAttrs(nil))
}

func TestPluginHandler_WithGroup(t *testing.T) {
	t.Parallel()

	handler := NewOpenVPNPluginLogger(testutil.Callbacks())

	require.Same(t, handler, handler.WithGroup("group"))
}

func TestPluginHandler_Enabled(t *testing.T) {
	t.Parallel()

	handler := NewOpenVPNPluginLogger(testutil.Callbacks())

	require.False(t, handler.Enabled(t.Context(), slog.LevelDebug-1))
	require.True(t, handler.Enabled(t.Context(), slog.LevelDebug))
	require.True(t, handler.Enabled(t.Context(), slog.LevelInfo))
	require.True(t, handler.Enabled(t.Context(), slog.LevelWarn))
	require.True(t, handler.Enabled(t.Context(), slog.LevelError))
}

func TestPluginHandler_AppendAttr(t *testing.T) {
	t.Parallel()

	handler := NewOpenVPNPluginLogger(testutil.Callbacks())

	for _, tc := range []struct {
		name     string
		attr     slog.Attr
		expected string
	}{
		{
			name:     "empty",
			attr:     slog.Attr{},
			expected: "",
		},
		{
			name:     "string",
			attr:     slog.String("key", `value "quoted"`),
			expected: ` key="value \"quoted\""`,
		},
		{
			name:     "time",
			attr:     slog.Time("at", time.Date(2026, time.July, 2, 10, 11, 12, 13, time.UTC)),
			expected: " at=2026-07-02T10:11:12.000000013Z",
		},
		{
			name: "group",
			attr: slog.Group(
				"session",
				slog.String("id", "sid-1"),
				slog.Int("cid", 7),
			),
			expected: ` session={ id="sid-1" cid=7}`,
		},
		{
			name:     "empty group",
			attr:     slog.Group("session"),
			expected: "",
		},
		{
			name:     "duration",
			attr:     slog.Duration("wait", 1500*time.Microsecond),
			expected: " wait=1.5ms",
		},
		{
			name:     "int",
			attr:     slog.Int64("cid", 7),
			expected: " cid=7",
		},
		{
			name:     "uint",
			attr:     slog.Uint64("cid", 7),
			expected: " cid=7",
		},
		{
			name:     "float",
			attr:     slog.Float64("score", 1.25),
			expected: " score=1.250000",
		},
		{
			name:     "bool",
			attr:     slog.Bool("ok", true),
			expected: " ok=true",
		},
		{
			name:     "any",
			attr:     slog.Any("values", []string{"one", "two"}),
			expected: " values=[one two]",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.expected, string(handler.appendAttr(nil, tc.attr)))
		})
	}
}

func TestPluginHandler_PluginLogLevel(t *testing.T) {
	t.Parallel()

	handler := NewOpenVPNPluginLogger(testutil.Callbacks())

	for _, tc := range []struct {
		name     string
		level    slog.Level
		expected c.PLogLevel
	}{
		{
			name:     "debug",
			level:    slog.LevelDebug,
			expected: c.PLogDebug,
		},
		{
			name:     "info",
			level:    slog.LevelInfo,
			expected: c.PLogNote,
		},
		{
			name:     "warn",
			level:    slog.LevelWarn,
			expected: c.PLogWarn,
		},
		{
			name:     "error",
			level:    slog.LevelError,
			expected: c.PLogErr,
		},
		{
			name:     "custom info offset",
			level:    slog.LevelInfo + 1,
			expected: c.PLogNote,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.expected, handler.pluginLogLevel(tc.level))
		})
	}
}
