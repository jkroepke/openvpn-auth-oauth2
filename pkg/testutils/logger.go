package testutils

import (
	"bytes"
	"log/slog"
)

type Logger struct {
	*slog.Logger
	*bytes.Buffer
}

func NewTestLogger() *Logger {
	buffer := new(bytes.Buffer)

	return &Logger{
		slog.New(slog.NewTextHandler(buffer, nil)),
		buffer,
	}
}

func (l Logger) GetLogs() string {
	return l.Buffer.String()
}
