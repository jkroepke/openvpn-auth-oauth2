package testutils

import (
	"bytes"
	"log/slog"
	"sync"
)

type Logger struct {
	*slog.Logger
	*SyncBuffer
}

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

func (l Logger) GetLogs() string {
	return l.SyncBuffer.String()
}

type SyncBuffer struct {
	buffer bytes.Buffer
	mutex  sync.Mutex
}

// Write appends the contents of p to the buffer, growing the buffer as needed.
// It returns the number of bytes written.
func (s *SyncBuffer) Write(p []byte) (int, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.buffer.Write(p) //nolint:wrapcheck
}

// String returns the contents of the unread portion of the buffer
// as a string.
// If the SyncBuffer is a nil pointer, it returns "<nil>".
func (s *SyncBuffer) String() string {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.buffer.String()
}
