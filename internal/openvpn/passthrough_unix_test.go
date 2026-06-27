//go:build unix

package openvpn //nolint:testpackage // Verify the private listener closer used by the shutdown path.

import (
	"log/slog"
	"net/url"
	"os"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/nettest"
)

func TestClient_SetupPassThroughListener_UnixSocketLifecycle(t *testing.T) {
	t.Parallel()

	path, err := nettest.LocalPath()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(path) })

	conf := config.Defaults
	conf.OpenVPN.Passthrough.Address = types.URL{URL: &url.URL{Scheme: SchemeUnix, Path: path}}

	client := New(slog.New(slog.DiscardHandler), &conf)
	_, closer, err := client.setupPassThroughListener(t.Context())
	require.NoError(t, err)
	require.FileExists(t, path)

	closer()

	_, err = os.Lstat(path)
	require.ErrorIs(t, err, os.ErrNotExist)
}
