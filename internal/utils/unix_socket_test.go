//go:build unix

package utils_test

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/utils"
	"github.com/stretchr/testify/require"
)

func TestPrepareUnixSocket(t *testing.T) {
	t.Parallel()

	t.Run("missing", func(t *testing.T) {
		t.Parallel()

		require.NoError(t, utils.PrepareUnixSocket(t.Context(), filepath.Join(t.TempDir(), "missing.sock")))
	})

	t.Run("stale", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "stale.sock")

		var listenConfig net.ListenConfig

		listener, err := listenConfig.Listen(t.Context(), "unix", path)
		require.NoError(t, err)

		unixListener, ok := listener.(*net.UnixListener)
		require.True(t, ok)
		unixListener.SetUnlinkOnClose(false)
		require.NoError(t, listener.Close())

		require.NoError(t, utils.PrepareUnixSocket(t.Context(), path))
		_, err = os.Lstat(path)
		require.ErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("active", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "active.sock")

		var listenConfig net.ListenConfig

		listener, err := listenConfig.Listen(t.Context(), "unix", path)
		require.NoError(t, err)
		t.Cleanup(func() { _ = listener.Close() })

		err = utils.PrepareUnixSocket(t.Context(), path)
		require.ErrorContains(t, err, "already in use")
		require.FileExists(t, path)
	})

	t.Run("regular file", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "regular-file")
		require.NoError(t, os.WriteFile(path, []byte("keep"), 0o600))

		err := utils.PrepareUnixSocket(t.Context(), path)
		require.ErrorContains(t, err, "is not a socket")
		require.FileExists(t, path)
	})
}
