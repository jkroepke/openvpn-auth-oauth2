//go:build windows && plan9

package main

import (
	"fmt"
	"log/slog"
)

func newSyslogLogger(_ slog.Level) (*slog.Logger, error) {
	return nil, fmt.Errorf("syslog logging is not supported on this operating system")
}
