//go:build !windows && !plan9

package main

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func testLogger(level slog.Level, output *[4]string) *slog.Logger {
	var sinks [4]func(string) error

	for i := range sinks {
		sinks[i] = func(message string) error {
			output[i] = message

			return nil
		}
	}

	return slog.New(syslogHandler{sinks: sinks, level: level})
}

func TestSyslogSeverity(t *testing.T) {
	t.Parallel()

	var got [4]string

	logger := testLogger(slog.LevelDebug, &got).
		With(slog.String("node", "vpn1")).
		WithGroup("auth").
		With(slog.String("user", "alice"))

	for i, level := range []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError} {
		logger.LogAttrs(context.Background(), level, "hello")

		if got[i] != `hello node="vpn1" auth.user="alice"` {
			t.Fatalf("priority %d: %q", i, got[i])
		}
	}
}

func TestSyslogQuotedNestedAndMultiline(t *testing.T) {
	t.Parallel()

	var got [4]string

	logger := testLogger(slog.LevelInfo, &got).
		WithGroup("outer").
		With(slog.String("base", "one"))

	logger.Info("line1\nline2",
		slog.Group("inner",
			slog.String("user", "a b"),
			slog.Any("err", errors.New("bad\r\nresponse")),
		),
	)

	want := `line1 | line2 outer.base="one" outer.inner.user="a b" outer.inner.err="bad | response"`

	if got[1] != want {
		t.Fatalf("want %q got %q", want, got[1])
	}

	if strings.Contains(got[1], `\n`) || strings.Contains(got[1], "\n") {
		t.Fatalf("escaped newlines %q", got[1])
	}
}

func TestSyslogFiltering(t *testing.T) {
	t.Parallel()

	var got [4]string

	logger := testLogger(slog.LevelWarn, &got)
	logger.Debug("debug")
	logger.Info("info")

	if got != [4]string{} {
		t.Fatalf("filtered data: %q", got)
	}

	logger.Warn("warning")

	if got[2] != "warning" {
		t.Fatalf("warn: %q", got[2])
	}
}

func TestSyslogAlwaysQuotesValues(t *testing.T) {
	t.Parallel()

	var got [4]string

	logger := testLogger(slog.LevelInfo, &got)
	logger.Info("sample",
		slog.String("empty", ""),
		slog.Int("number", 42),
		slog.String("equals", "a=b"),
		slog.String("quote", `a"b`),
	)

	want := `sample empty="" number="42" equals="a=b" quote="a\"b"`

	if got[1] != want {
		t.Fatalf("want %q, got %q", want, got[1])
	}
}
