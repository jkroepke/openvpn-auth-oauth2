package utils

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

const unixSocketProbeTimeout = time.Second

// PrepareUnixSocket removes path when it is a stale Unix socket. It refuses to
// remove active sockets and other filesystem objects.
func PrepareUnixSocket(ctx context.Context, path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("inspect unix socket %q: %w", path, err)
	}

	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("unix socket path %q exists and is not a socket", path)
	}

	dialer := net.Dialer{Timeout: unixSocketProbeTimeout}

	conn, err := dialer.DialContext(ctx, "unix", path)
	if err == nil {
		_ = conn.Close()

		return fmt.Errorf("unix socket path %q is already in use", path)
	}

	if !errors.Is(err, syscall.ECONNREFUSED) {
		return fmt.Errorf("probe unix socket %q: %w", path, err)
	}

	return removeStaleUnixSocket(path, info)
}

func removeStaleUnixSocket(path string, previousInfo os.FileInfo) error {
	currentInfo, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("inspect stale unix socket %q: %w", path, err)
	}

	if currentInfo.Mode()&os.ModeSocket == 0 || !os.SameFile(previousInfo, currentInfo) {
		return fmt.Errorf("unix socket path %q changed while checking it", path)
	}

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale unix socket %q: %w", path, err)
	}

	return nil
}
