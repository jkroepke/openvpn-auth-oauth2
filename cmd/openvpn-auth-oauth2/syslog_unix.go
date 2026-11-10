//go:build !windows && !plan9

package main

import (
	"context"
	"fmt"
	"log/slog"
	"log/syslog"
	"strconv"
	"strings"
	"sync"
)

// Reuse the same local syslog connection across configuration reloads.
//
//nolint:gochecknoglobals // A process-wide connection avoids leaking sockets on reload.
var openSyslog = sync.OnceValues(func() (*syslog.Writer, error) {
	return syslog.New(syslog.LOG_DAEMON|syslog.LOG_INFO, "openvpn-auth-oauth2")
})

func newSyslogLogger(level slog.Level) (*slog.Logger, error) {
	writer, err := openSyslog()
	if err != nil {
		return nil, fmt.Errorf("connect to local syslog: %w", err)
	}

	return slog.New(syslogHandler{sinks: [4]func(string) error{
		writer.Debug, writer.Info, writer.Warning, writer.Err,
	}, level: level}), nil
}

type syslogHandler struct {
	sinks [4]func(string) error
	attrs string // preformatted attributes from WithAttrs
	group string // prefix for subsequent attributes
	level slog.Level
}

func (h syslogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

func (h syslogHandler) Handle(_ context.Context, record slog.Record) error {
	var builder strings.Builder

	builder.WriteString(normalizeSyslogNewlines(record.Message))

	if h.attrs != "" {
		if builder.Len() > 0 {
			builder.WriteByte(' ')
		}

		builder.WriteString(h.attrs)
	}

	record.Attrs(func(attr slog.Attr) bool {
		appendSyslogAttr(&builder, h.group, attr)

		return true
	})

	switch {
	case record.Level >= slog.LevelError:
		return h.sinks[3](builder.String())
	case record.Level >= slog.LevelWarn:
		return h.sinks[2](builder.String())
	case record.Level >= slog.LevelInfo:
		return h.sinks[1](builder.String())
	default:
		return h.sinks[0](builder.String())
	}
}

func (h syslogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	var builder strings.Builder

	builder.WriteString(h.attrs)

	for _, attr := range attrs {
		appendSyslogAttr(&builder, h.group, attr)
	}

	h.attrs = builder.String()

	return h
}

func (h syslogHandler) WithGroup(name string) slog.Handler {
	if name != "" {
		h.group += name + "."
	}

	return h
}

func appendSyslogAttr(builder *strings.Builder, group string, attr slog.Attr) {
	if attr.Equal(slog.Attr{}) {
		return
	}

	value := attr.Value.Resolve()
	if value.Kind() == slog.KindGroup {
		if attr.Key != "" {
			group += attr.Key + "."
		}

		for _, nested := range value.Group() {
			appendSyslogAttr(builder, group, nested)
		}

		return
	}

	if builder.Len() > 0 {
		builder.WriteByte(' ')
	}

	builder.WriteString(group)
	builder.WriteString(attr.Key)
	builder.WriteByte('=')
	builder.WriteString(strconv.Quote(normalizeSyslogNewlines(value.String())))
}

func normalizeSyslogNewlines(value string) string {
	value = strings.ReplaceAll(value, "\r\n", " | ")
	value = strings.ReplaceAll(value, "\r", " | ")

	return strings.ReplaceAll(value, "\n", " | ")
}
