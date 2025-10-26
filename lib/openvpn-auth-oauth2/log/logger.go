package log

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
	"unsafe"

	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/c"
)

// PluginHandler implements slog.Handler to integrate Go's structured logging with
// OpenVPN's plugin logging system. It forwards log messages to OpenVPN using the
// plugin_log callback function.
type PluginHandler struct {
	mu           *sync.Mutex
	cb           *c.OpenVPNPluginCallbacks
	opts         Options
	preformatted []byte
}

// Options configures the behavior of the PluginHandler.
type Options struct {
	// Level reports the minimum level to log.
	// Levels with lower levels are discarded.
	// If nil, the Handler uses [slog.LevelInfo].
	Level slog.Leveler
}

// NewOpenVPNPluginLogger creates a new PluginHandler that sends log messages
// to OpenVPN via the plugin callback interface.
//
// Parameters:
//   - cb: OpenVPN plugin callbacks structure containing the plugin_log function
//   - opts: Optional configuration for the handler (can be nil for defaults)
//
// Returns:
//   - *PluginHandler: A new handler that implements slog.Handler
func NewOpenVPNPluginLogger(cb *c.OpenVPNPluginCallbacks) *PluginHandler {
	handler := &PluginHandler{cb: cb, mu: &sync.Mutex{}}
	handler.opts.Level = slog.LevelDebug

	return handler
}

func (h *PluginHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}

	handler := *h

	// Pre-format the attributes.
	for _, a := range attrs {
		handler.preformatted = handler.appendAttr(handler.preformatted, a)
	}

	return &handler
}

func (h *PluginHandler) WithGroup(_ string) slog.Handler {
	panic("implement me")
}

func (h *PluginHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.opts.Level.Level()
}

func (h *PluginHandler) Handle(_ context.Context, record slog.Record) error {
	buf := make([]byte, 0, 1024)
	buf = fmt.Appendf(buf, "%s: %s", record.Level, record.Message)

	// Insert preformatted attributes just after built-in ones.
	buf = append(buf, h.preformatted...)

	record.Attrs(func(a slog.Attr) bool {
		buf = h.appendAttr(buf, a)

		return true
	})

	h.mu.Lock()

	msg := c.CString(string(buf))

	c.PluginLog(h.cb, h.pluginLogLevel(record.Level), msg)

	C.free(unsafe.Pointer(msg))

	h.mu.Unlock()

	return nil
}

//nolint:cyclop
func (h *PluginHandler) appendAttr(buf []byte, attr slog.Attr) []byte {
	// Resolve the Attr's value before doing anything else.
	attr.Value = attr.Value.Resolve()
	// Ignore empty Attrs.
	if attr.Equal(slog.Attr{}) {
		return buf
	}

	switch attr.Value.Kind() {
	case slog.KindString:
		// Quote string values, to make them easy to parse.
		buf = fmt.Appendf(buf, " %s=%q", attr.Key, attr.Value.String())
	case slog.KindTime:
		// write times in a standard way, without the monotonic time.
		buf = fmt.Appendf(buf, " %s=%s", attr.Key, attr.Value.Time().Format(time.RFC3339Nano))
	case slog.KindGroup:
		attrs := attr.Value.Group()
		// Ignore empty groups.
		if len(attrs) == 0 {
			return buf
		}
		// If the key is non-empty, write it out and indent the rest of the attrs.
		// Otherwise, inline the attrs.
		if attr.Key != "" {
			buf = fmt.Appendf(buf, " %s={", attr.Key)
		}

		for _, ga := range attrs {
			buf = h.appendAttr(buf, ga)
		}

		if attr.Key != "" {
			buf = fmt.Appendf(buf, "}")
		}
	case slog.KindAny:
		// Use the default string representation for any other kinds.
		buf = fmt.Appendf(buf, " %s=%v", attr.Key, attr.Value.Any())
	case slog.KindDuration:
		buf = fmt.Appendf(buf, " %s=%s", attr.Key, attr.Value.Duration().String())
	case slog.KindInt64:
		buf = fmt.Appendf(buf, " %s=%d", attr.Key, attr.Value.Int64())
	case slog.KindUint64:
		buf = fmt.Appendf(buf, " %s=%d", attr.Key, attr.Value.Uint64())
	case slog.KindFloat64:
		buf = fmt.Appendf(buf, " %s=%f", attr.Key, attr.Value.Float64())
	case slog.KindBool:
		buf = fmt.Appendf(buf, " %s=%t", attr.Key, attr.Value.Bool())
	case slog.KindLogValuer:
		panic("implement me")
	default:
		buf = fmt.Appendf(buf, " %s=%s", attr.Key, attr.Value)
	}

	return buf
}

func (h *PluginHandler) pluginLogLevel(level slog.Level) c.PLogLevel {
	switch level {
	case slog.LevelError:
		return c.PLogErr
	case slog.LevelWarn:
		return c.PLogWarn
	case slog.LevelDebug:
		return c.PLogDebug
	case slog.LevelInfo:
		fallthrough
	default:
		return c.PLogNote
	}
}
