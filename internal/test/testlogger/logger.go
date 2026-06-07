package testlogger

import (
	"bytes"
	"io"
	"log/slog"
	"sync"
)

var (
	_ io.Writer = (*Logger)(nil)
	_ io.Writer = (*SyncBuffer)(nil)
)

// Logger combines slog.Logger with a synchronized buffer used in tests.
type Logger struct {
	logger *slog.Logger
	buffer *SyncBuffer
}

// New returns a logger that stores all logs in memory so tests can inspect them.
func New() *Logger {
	syncBuffer := NewSyncBuffer()
	syncBuffer.buffer.Grow(16 << 20)

	return &Logger{
		logger: slog.New(slog.NewTextHandler(syncBuffer, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})),
		buffer: syncBuffer,
	}
}

func (l *Logger) Logger() *slog.Logger {
	return l.logger
}

func (l *Logger) String() string {
	return l.buffer.String()
}

func (l *Logger) Write(p []byte) (int, error) {
	return l.buffer.Write(p)
}

// SyncBuffer is a bytes.Buffer protected by a mutex for concurrent writes.
type SyncBuffer struct {
	buffer bytes.Buffer
	mutex  sync.Mutex
}

func NewSyncBuffer() *SyncBuffer {
	return &SyncBuffer{}
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
