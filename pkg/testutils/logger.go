package testutils

import (
	"bytes"
	"log/slog"
	"sync"
)

type Logger struct {
	*slog.Logger
	*Buffer
}

func NewTestLogger() *Logger {
	buffer := new(Buffer)

	return &Logger{
		slog.New(slog.NewTextHandler(buffer, nil)),
		buffer,
	}
}

func (l Logger) GetLogs() string {
	return l.Buffer.String()
}

type Buffer struct {
	buffer bytes.Buffer
	mutex  sync.Mutex
}

// Write appends the contents of p to the buffer, growing the buffer as needed.
// It returns the number of bytes written.
func (s *Buffer) Write(p []byte) (n int, err error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.buffer.Write(p)
}

// String returns the contents of the unread portion of the buffer
// as a string.
// If the Buffer is a nil pointer, it returns "<nil>".
func (s *Buffer) String() string {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.buffer.String()
}
