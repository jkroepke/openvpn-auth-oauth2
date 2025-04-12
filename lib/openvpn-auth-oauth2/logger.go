package main

/*
#include <openvpn-plugin.h>
static char *MODULE = "openvpn-auth-oauth2";

// A wrapper function is needed because go is not able to call C pointer functions
// https://stackoverflow.com/questions/37157379/passing-function-pointer-to-the-c-code-using-cgo
int plugin_log(struct openvpn_plugin_callbacks* cb, int flags, char *msg) {
	cb->plugin_log(flags, MODULE, "%s", msg);
	return 0;
}
*/
import "C"

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
	"unsafe"
)

type PluginHandler struct {
	mu           *sync.Mutex
	cb           *C.struct_openvpn_plugin_callbacks
	opts         Options
	preformatted []byte
}

type Options struct {
	// Level reports the minimum level to log.
	// Levels with lower levels are discarded.
	// If nil, the Handler uses [slog.LevelInfo].
	Level slog.Leveler
}

func NewOpenVPNPluginLogger(cb *C.struct_openvpn_plugin_callbacks, opts *Options) *PluginHandler {
	handler := &PluginHandler{cb: cb, mu: &sync.Mutex{}}
	if opts != nil {
		handler.opts = *opts
	}
	if handler.opts.Level == nil {
		handler.opts.Level = slog.LevelInfo
	}

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

	msg := C.CString(string(buf))

	C.plugin_log(h.cb, h.pluginLogLevel(record.Level), msg) //nolint:nlreturn

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

func (h *PluginHandler) pluginLogLevel(level slog.Level) C.int {
	switch level {
	case slog.LevelError:
		return C.PLOG_ERR
	case slog.LevelWarn:
		return C.PLOG_WARN
	case slog.LevelDebug:
		return C.PLOG_DEBUG
	case slog.LevelInfo:
		fallthrough
	default:
		return C.PLOG_NOTE
	}
}
