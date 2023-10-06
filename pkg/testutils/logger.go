package testutils

import (
	"context"
	"log/slog"
)

type Logger struct{}

func (l Logger) Enabled(_ context.Context, _ slog.Level) bool {
	return false
}

func (l Logger) Handle(_ context.Context, _ slog.Record) error {
	return nil
}

func (l Logger) WithAttrs(_ []slog.Attr) slog.Handler {
	return l
}

func (l Logger) WithGroup(_ string) slog.Handler {
	return l
}

func NewTestLogger() *slog.Logger {
	return slog.New(Logger{})
}
