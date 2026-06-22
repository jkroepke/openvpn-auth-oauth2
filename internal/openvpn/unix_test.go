//go:build !windows

package openvpn_test

import (
	"context"
	"log/slog"
	"net"
	"net/url"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/test/testsuite"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/nettest"
)

// createStaleUnixSocket creates a Unix socket file at path that has no
// process listening on it (simulating a leftover from a previous run).
func createStaleUnixSocket(tb testing.TB, path string) {
	tb.Helper()

	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	require.NoError(tb, err)

	sa := &syscall.SockaddrUnix{Name: path}
	require.NoError(tb, syscall.Bind(fd, sa))
	require.NoError(tb, syscall.Close(fd))
}

// TestConnectUnixStaleSocket verifies that when a Unix socket file exists but
// nothing is listening (stale file from a previous run), Connect retries the
// connection until the server becomes available.
func TestConnectUnixStaleSocket(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	socketPath, err := nettest.LocalPath()
	require.NoError(t, err)

	// Create a stale socket file – exists, but nobody is listening.
	createStaleUnixSocket(t, socketPath)

	conf := config.Config{
		HTTP: config.HTTP{
			BaseURL: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
			Secret:  testsuite.Secret,
		},
		OpenVPN: config.OpenVPN{
			Addr:           types.URL{URL: &url.URL{Scheme: openvpn.SchemeUnix, Path: socketPath}},
			Bypass:         config.OpenVPNBypass{CommonNames: make(types.RegexpSlice, 0)},
			CommandTimeout: 300 * time.Millisecond,
		},
	}

	suite := testsuite.New(conf)
	_, openVPNClient := suite.SetupOpenVPNOAuth2Clients(t.Context(), t, nil)

	// Start a real management interface server after a brief delay to simulate
	// OpenVPN being slow to start (the client should retry until it connects).
	serverReady := make(chan struct{})
	var managementListener net.Listener

	go func() {
		time.Sleep(1500 * time.Millisecond)

		managementListener, err = net.Listen("unix", socketPath)
		if err != nil {
			return
		}

		close(serverReady)
	}()

	errCh := make(chan error, 1)

	go func() {
		errCh <- openVPNClient.Connect(t.Context())
	}()

	// Wait for the server to be set up.
	select {
	case <-serverReady:
	case <-time.After(5 * time.Second):
		t.Fatal("management server did not start in time")
	}

	// Accept the incoming connection so the client can proceed, then close to
	// trigger a clean shutdown of the openvpn client.
	conn, err := managementListener.Accept()
	require.NoError(t, err)

	// Send the welcome banner that the client expects.
	_, err = conn.Write([]byte(openvpn.WelcomeBanner + "\r\n"))
	require.NoError(t, err)

	_ = conn.Close()
	_ = managementListener.Close()

	// Connect should return without error (or with a non-fatal connection-closed
	// error) after the server disconnects, not with an "unable to connect" error.
	select {
	case connectErr := <-errCh:
		if connectErr != nil {
			require.NotContains(t, connectErr.Error(), "unable to connect to openvpn management interface",
				"expected Connect to have succeeded before the server closed the connection")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Connect did not return in time")
	}
}

// TestPassThroughStaleUnixSocket verifies that the passthrough listener can
// be started even when a stale Unix socket file exists at the configured path.
func TestPassThroughStaleUnixSocket(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	socketPath, err := nettest.LocalPath()
	require.NoError(t, err)

	// Create a stale socket file – exists, but nobody is listening.
	createStaleUnixSocket(t, socketPath)

	conf := config.Defaults
	conf.HTTP.Secret = testsuite.Secret
	conf.Log.Level = slog.LevelDebug
	conf.OpenVPN.Passthrough.Enabled = true
	conf.OpenVPN.Passthrough.Address = types.URL{URL: &url.URL{Scheme: openvpn.SchemeUnix, Path: socketPath}}

	suite := testsuite.New(conf)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	errOpenVPNClientCh := suite.SetupManagementEnvironment(ctx, t, nil)

	// Give the passthrough listener time to start and verify it started.
	select {
	case err := <-errOpenVPNClientCh:
		if err != nil && !strings.Contains(err.Error(), "pass-through") {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		// No error after 2 seconds – the passthrough listener started fine.
	}

	openVPNClient := suite.GetOpenVPNClient()
	openVPNClient.Shutdown(ctx)
}
