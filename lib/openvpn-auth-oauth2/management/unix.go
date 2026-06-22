//go:build (darwin || linux || openbsd || freebsd) && cgo

package management

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"syscall"
)

// removeStaleUnixSocket removes a Unix socket file when it exists but is not
// actively used by another process. The check is performed by trying to
// connect to the socket: if the connection is refused the socket file is
// considered stale and is removed so that a new listener can bind to the
// same path. If the connection succeeds the file is left untouched because
// another process is already serving on it.
func removeStaleUnixSocket(ctx context.Context, logger *slog.Logger, path string) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}

	conn, err := net.Dial("unix", path)
	if err == nil {
		// Another process is actively listening – leave the socket alone.
		_ = conn.Close()

		return nil
	}

	if !errors.Is(err, syscall.ECONNREFUSED) {
		// Unexpected error – do not touch the file.
		return nil
	}

	// Connection was refused: no process is listening on this path.
	logger.LogAttrs(ctx, slog.LevelDebug, "removing stale unix socket file", slog.String("path", path))

	if err = os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("unable to remove stale unix socket file %s: %w", path, err)
	}

	return nil
}
