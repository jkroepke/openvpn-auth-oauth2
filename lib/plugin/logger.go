//go:build linux

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
	opts         Options
	preformatted []byte
	mu           *sync.Mutex
	cb           *C.struct_openvpn_plugin_callbacks
}

func (h *PluginHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	h2 := *h

	// Pre-format the attributes.
	for _, a := range attrs {
		h2.preformatted = h2.appendAttr(h2.preformatted, a)
	}

	return &h2
}

func (h *PluginHandler) WithGroup(_ string) slog.Handler {
	// TODO implement me
	panic("implement me")
}

type Options struct {
	// Level reports the minimum level to log.
	// Levels with lower levels are discarded.
	// If nil, the Handler uses [slog.LevelInfo].
	Level slog.Leveler
}

func New(cb *C.struct_openvpn_plugin_callbacks, opts *Options) *PluginHandler {
	h := &PluginHandler{cb: cb, mu: &sync.Mutex{}}
	if opts != nil {
		h.opts = *opts
	}
	if h.opts.Level == nil {
		h.opts.Level = slog.LevelInfo
	}

	return h
}

func (h *PluginHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.opts.Level.Level()
}

func (h *PluginHandler) Handle(_ context.Context, r slog.Record) error {
	buf := make([]byte, 0, 1024)
	buf = fmt.Appendf(buf, "%s: %s", r.Level, r.Message)

	// Insert preformatted attributes just after built-in ones.
	buf = append(buf, h.preformatted...)

	r.Attrs(func(a slog.Attr) bool {
		buf = h.appendAttr(buf, a)
		return true
	})

	h.mu.Lock()
	defer h.mu.Unlock()

	msg := C.CString(string(buf))
	defer C.free(unsafe.Pointer(msg))

	C.plugin_log(h.cb, h.pluginLogLevel(r.Level), msg)

	return nil
}

func (h *PluginHandler) appendAttr(buf []byte, a slog.Attr) []byte {
	// Resolve the Attr's value before doing anything else.
	a.Value = a.Value.Resolve()
	// Ignore empty Attrs.
	if a.Equal(slog.Attr{}) {
		return buf
	}
	switch a.Value.Kind() {
	case slog.KindString:
		// Quote string values, to make them easy to parse.
		buf = fmt.Appendf(buf, " %s=%q", a.Key, a.Value.String())
	case slog.KindTime:
		// Write times in a standard way, without the monotonic time.
		buf = fmt.Appendf(buf, " %s=%s", a.Key, a.Value.Time().Format(time.RFC3339Nano))
	case slog.KindGroup:
		attrs := a.Value.Group()
		// Ignore empty groups.
		if len(attrs) == 0 {
			return buf
		}
		// If the key is non-empty, write it out and indent the rest of the attrs.
		// Otherwise, inline the attrs.
		if a.Key != "" {
			buf = fmt.Appendf(buf, " %s={", a.Key)
		}
		for _, ga := range attrs {
			buf = h.appendAttr(buf, ga)
		}
		if a.Key != "" {
			buf = fmt.Appendf(buf, "}")
		}
	default:
		buf = fmt.Appendf(buf, " %s=%s", a.Key, a.Value)
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
