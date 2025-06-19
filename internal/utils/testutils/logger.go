package testutils

import (
	"bytes"
	"log/slog"
	"sync"
)

// Logger combines slog.Logger with a synchronized buffer used in tests.
type Logger struct {
	*slog.Logger
	*SyncBuffer
}

// NewTestLogger returns a logger that stores all logs in memory so tests can
// inspect them.
func NewTestLogger() *Logger {
	syncBuffer := new(SyncBuffer)
	syncBuffer.buffer.Grow(16 << 20)

	return &Logger{
		slog.New(slog.NewTextHandler(syncBuffer, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})),
		syncBuffer,
	}
}

// GetLogs returns the accumulated log output as a string.
func (l Logger) GetLogs() string {
	return l.String()
}

// SyncBuffer is a bytes.Buffer protected by a mutex for concurrent writes.
type SyncBuffer struct {
	buffer bytes.Buffer
	mutex  sync.Mutex
}

// Write appends bytes to the buffer. It is safe for concurrent use.
func (s *SyncBuffer) Write(p []byte) (int, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.buffer.Write(p) //nolint:wrapcheck
}

// String returns the buffered data as a string.
func (s *SyncBuffer) String() string {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.buffer.String()
}
