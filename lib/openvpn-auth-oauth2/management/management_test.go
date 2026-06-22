//go:build (darwin || linux || openbsd || freebsd) && cgo

package management_test

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/test/testlogger"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/test/testsuite"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/version"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/management"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/nettest"
)

func TestServer_Listen(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		protocol string
	}{
		{
			protocol: "tcp",
		},
		{
			protocol: "unix",
		},
	} {
		t.Run(tc.protocol, func(t *testing.T) {
			t.Parallel()

			managementInterface, err := nettest.NewLocalListener(tc.protocol)
			require.NoError(t, err)

			err = managementInterface.Close()
			require.NoError(t, err)

			managementServer := management.NewServer(slog.New(slog.DiscardHandler), "")
			err = managementServer.Listen(t.Context(), fmt.Sprintf("%s://%s", managementInterface.Addr().Network(), managementInterface.Addr().String()))
			require.NoError(t, err)

			t.Cleanup(managementServer.Close)

			var dialer net.Dialer

			client, err := dialer.DialContext(t.Context(), tc.protocol, managementInterface.Addr().String())
			require.NoError(t, err)

			t.Cleanup(func() {
				_ = client.Close()
			})

			clientConn := testsuite.NewConn(client)

			clientConn.ExpectMessage(t, openvpn.WelcomeBanner)
			clientConn.SendMessagef(t, "")
			clientConn.SendAndExpectMessage(t, "hold release", "SUCCESS: hold released")
			clientConn.SendAndExpectMessage(t, "version", fmt.Sprintf("OpenVPN Version: openvpn-auth-oauth2 %s\nManagement Interface Version: 5\nEND", version.Version))
			clientConn.SendAndExpectMessage(t, "help", "SUCCESS: help")
			clientConn.SendAndExpectMessage(t, "unknown", "ERROR: unknown command, enter 'help' for more options")

			require.NoError(t, client.Close())

			client, err = dialer.DialContext(t.Context(), tc.protocol, managementInterface.Addr().String())
			require.NoError(t, err)

			clientConn = testsuite.NewConn(client)

			clientConn.ExpectMessage(t, openvpn.WelcomeBanner)
			clientConn.SendAndExpectMessage(t, "exit", "SUCCESS: exiting")

			client, err = dialer.DialContext(t.Context(), tc.protocol, managementInterface.Addr().String())
			require.NoError(t, err)

			clientConn = testsuite.NewConn(client)

			clientConn.ExpectMessage(t, openvpn.WelcomeBanner)
			clientConn.SendAndExpectMessage(t, "quit", "SUCCESS: exiting")

			client, err = dialer.DialContext(t.Context(), tc.protocol, managementInterface.Addr().String())
			require.NoError(t, err)
			require.NoError(t, client.Close())
		})
	}
}

func TestServer_Listen_UnixSocketLifecycle(t *testing.T) {
	t.Parallel()

	path, err := nettest.LocalPath()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(path) })

	managementServer := management.NewServer(slog.New(slog.DiscardHandler), "")
	require.NoError(t, managementServer.Listen(t.Context(), "unix://"+path))
	require.FileExists(t, path)

	managementServer.Close()

	_, err = os.Lstat(path)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestServer_Close_DoesNotWarnAboutClosedConnection(t *testing.T) {
	t.Parallel()

	managementInterface, err := nettest.NewLocalListener("tcp")
	require.NoError(t, err)
	require.NoError(t, managementInterface.Close())

	logger := testlogger.New()
	managementServer := management.NewServer(logger.Logger(), "")
	require.NoError(t, managementServer.Listen(t.Context(), "tcp://"+managementInterface.Addr().String()))

	var dialer net.Dialer

	client, err := dialer.DialContext(t.Context(), "tcp", managementInterface.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	clientConn := testsuite.NewConn(client)
	clientConn.ExpectMessage(t, openvpn.WelcomeBanner)

	managementServer.Close()

	require.Eventually(t, func() bool {
		return strings.Contains(logger.String(), "management client disconnected")
	}, time.Second, 10*time.Millisecond)
	require.NotContains(t, logger.String(), "error handling management client")
}

func TestServer_Listen_ReplacesStaleUnixSocket(t *testing.T) {
	t.Parallel()

	path, err := nettest.LocalPath()
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.Remove(path) })

	var listenConfig net.ListenConfig

	stoppedListener, err := listenConfig.Listen(t.Context(), "unix", path)
	require.NoError(t, err)

	unixListener, ok := stoppedListener.(*net.UnixListener)
	require.True(t, ok)
	unixListener.SetUnlinkOnClose(false)
	require.NoError(t, stoppedListener.Close())
	require.FileExists(t, path)

	managementServer := management.NewServer(slog.New(slog.DiscardHandler), "")
	require.NoError(t, managementServer.Listen(t.Context(), "unix://"+path))
	t.Cleanup(managementServer.Close)

	dialer := net.Dialer{}
	client, err := dialer.DialContext(t.Context(), "unix", path)
	require.NoError(t, err)
	require.NoError(t, client.Close())
}

func TestServer_Listen_Invalid_Addr(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		addr string
	}{
		{
			addr: "invalid-address://localhost:8080",
		},
		{
			addr: "://",
		},
		{
			addr: "tcp://0.0.0.0:100000",
		},
	} {
		t.Run(tc.addr, func(t *testing.T) {
			t.Parallel()

			managementServer := management.NewServer(slog.New(slog.DiscardHandler), "")
			err := managementServer.Listen(t.Context(), tc.addr)
			require.Error(t, err)
		})
	}
}

func TestServer_Listen_Password_Correct(t *testing.T) {
	t.Parallel()

	managementInterface, err := nettest.NewLocalListener("tcp")
	require.NoError(t, err)

	err = managementInterface.Close()
	require.NoError(t, err)

	managementServer := management.NewServer(slog.New(slog.DiscardHandler), testsuite.Password)
	err = managementServer.Listen(t.Context(), fmt.Sprintf("%s://%s", managementInterface.Addr().Network(), managementInterface.Addr().String()))
	require.NoError(t, err)

	t.Cleanup(managementServer.Close)

	var dialer net.Dialer

	client, err := dialer.DialContext(t.Context(), "tcp", managementInterface.Addr().String())
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = client.Close()
	})

	clientConn := testsuite.NewConn(client)

	resp, err := clientConn.Reader().ReadString(':')
	require.NoError(t, err)
	require.Equal(t, "ENTER PASSWORD:", resp)

	clientConn.SendMessagef(t, testsuite.Password)
	clientConn.ExpectMessage(t, "SUCCESS: password is correct")
	clientConn.ExpectMessage(t, openvpn.WelcomeBanner)
	clientConn.SendMessagef(t, "quit")
}

func TestServer_Listen_Password_Incorrect(t *testing.T) {
	t.Parallel()

	managementInterface, err := nettest.NewLocalListener("tcp")
	require.NoError(t, err)

	err = managementInterface.Close()
	require.NoError(t, err)

	managementServer := management.NewServer(slog.New(slog.DiscardHandler), testsuite.Secret)
	err = managementServer.Listen(t.Context(), fmt.Sprintf("%s://%s", managementInterface.Addr().Network(), managementInterface.Addr().String()))
	require.NoError(t, err)

	t.Cleanup(managementServer.Close)

	var dialer net.Dialer

	client, err := dialer.DialContext(t.Context(), "tcp", managementInterface.Addr().String())
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = client.Close()
	})

	clientConn := testsuite.NewConn(client)

	resp, err := clientConn.Reader().ReadString(':')
	require.NoError(t, err)
	require.Equal(t, "ENTER PASSWORD:", resp)

	clientConn.SendMessagef(t, testsuite.Password)
	clientConn.ExpectMessage(t, "ERROR: bad password")
	clientConn.SendMessagef(t, "quit")
}

func TestServer_AuthPendingPoller(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		command string
		resp    string
		testFn  func(t *testing.T, response *management.Response)
	}{
		{
			name:    "client-auth-nt",
			command: "client-auth-nt 1 0",
			resp:    "SUCCESS: client-auth command succeeded",
			testFn: func(t *testing.T, response *management.Response) {
				t.Helper()

				require.Equal(t, uint32(1), response.ClientID)
				require.Equal(t, management.ClientAuthAccept, response.ClientAuth)
			},
		},
		{
			name:    "client-auth-nt invalid",
			command: "client-auth-nt A B",
			resp:    "ERROR: client-auth command failed",
		},
		{
			name:    "client-auth",
			command: "client-auth 2 0\r\npush \"reneg-sec 0\"\r\nEND",
			resp:    "SUCCESS: client-auth command succeeded",
			testFn: func(t *testing.T, response *management.Response) {
				t.Helper()

				require.Equal(t, uint32(2), response.ClientID)
				require.Equal(t, management.ClientAuthAccept, response.ClientAuth)
				require.Equal(t, "push \"reneg-sec 0\"", response.ClientConfig)
			},
		},
		{
			name:    "client-deny without reason",
			command: "client-deny 3 0",
			resp:    "SUCCESS: client-deny command succeeded",
			testFn: func(t *testing.T, response *management.Response) {
				t.Helper()

				require.Equal(t, uint32(3), response.ClientID)
				require.Equal(t, management.ClientAuthDeny, response.ClientAuth)
				require.Equal(t, "access denied", response.Message)
			},
		},
		{
			name:    "client-deny",
			command: "client-deny 3 0 \"internal error\"",
			resp:    "SUCCESS: client-deny command succeeded",
			testFn: func(t *testing.T, response *management.Response) {
				t.Helper()

				require.Equal(t, uint32(3), response.ClientID)
				require.Equal(t, management.ClientAuthDeny, response.ClientAuth)
				require.Equal(t, "internal error", response.Message)
			},
		},
		{
			name:    "client-pending-auth",
			command: "client-pending-auth 4 0 \"WEB_AUTH::https://sso.example.com/auth?session=xyz\" 300",
			resp:    "SUCCESS: client-pending-auth command succeeded",
			testFn: func(t *testing.T, response *management.Response) {
				t.Helper()

				require.Equal(t, uint32(4), response.ClientID)
				require.Equal(t, management.ClientAuthPending, response.ClientAuth)
				require.Equal(t, "WEB_AUTH::https://sso.example.com/auth?session=xyz", response.Message)
				require.Equal(t, "300", response.Timeout)
			},
		},
		{
			name:    "client-pending-auth without timeout",
			command: "client-pending-auth 4 0 \"WEB_AUTH::https://sso.example.com/auth?session=xyz\"",
			resp:    "ERROR: client-pending-auth command failed",
			testFn: func(t *testing.T, response *management.Response) {
				t.Helper()

				require.Equal(t, uint32(4), response.ClientID)
				require.Equal(t, management.ClientAuthDeny, response.ClientAuth)
				require.Equal(t, "internal error", response.Message)
			},
		},
		{
			name:    "invalid",
			command: "invalid",
			resp:    "ERROR: unknown command, enter 'help' for more options",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			managementInterface, err := nettest.NewLocalListener("tcp")
			require.NoError(t, err)

			err = managementInterface.Close()
			require.NoError(t, err)

			managementServer := management.NewServer(slog.New(slog.DiscardHandler), "")
			err = managementServer.Listen(t.Context(), fmt.Sprintf("%s://%s", managementInterface.Addr().Network(), managementInterface.Addr().String()))
			require.NoError(t, err)

			t.Cleanup(managementServer.Close)

			responseCh := make(chan *management.Response, 1)
			errCh := make(chan error, 1)

			var clientID uint64

			if !strings.HasSuffix(tc.name, "invalid") {
				clientID, err = strconv.ParseUint(strings.Split(tc.command, " ")[1], 10, 64)
				require.NoError(t, err)

				ctx := t.Context()

				go func() {
					response, err := managementServer.AuthPendingPoller(ctx, clientID, time.Second*5)

					errCh <- err

					responseCh <- response
				}()
			}

			var dialer net.Dialer

			client, err := dialer.DialContext(t.Context(), "tcp", managementInterface.Addr().String())
			require.NoError(t, err)

			t.Cleanup(func() {
				_ = client.Close()
			})

			clientConn := testsuite.NewConn(client)

			clientConn.ExpectMessage(t, openvpn.WelcomeBanner)
			clientConn.SendMessagef(t, tc.command)

			clientConn.ExpectMessage(t, tc.resp)

			if strings.HasSuffix(tc.name, "invalid") {
				return
			}

			require.NoError(t, <-errCh)

			response := <-responseCh
			require.NotNil(t, response)

			if tc.testFn == nil {
				return
			}

			tc.testFn(t, response)
		})
	}
}

func TestServer_AuthPendingPoller_Twice(t *testing.T) {
	t.Parallel()

	managementInterface, err := nettest.NewLocalListener("tcp")
	require.NoError(t, err)

	err = managementInterface.Close()
	require.NoError(t, err)

	managementServer := management.NewServer(slog.New(slog.DiscardHandler), "")
	err = managementServer.Listen(t.Context(), fmt.Sprintf("%s://%s", managementInterface.Addr().Network(), managementInterface.Addr().String()))
	require.NoError(t, err)

	t.Cleanup(managementServer.Close)

	errCh := make(chan error, 1)

	ctx := t.Context()

	go func() {
		_, err := managementServer.AuthPendingPoller(ctx, 0, time.Millisecond*10)
		errCh <- err
	}()

	go func() {
		_, err := managementServer.AuthPendingPoller(ctx, 0, time.Millisecond*10)
		errCh <- err
	}()

	require.EqualError(t, <-errCh, "poller for client ID 0 already exists")
	require.EqualError(t, <-errCh, "timeout waiting for client response")
}

func TestClientAuth_String(t *testing.T) {
	t.Parallel()

	require.Equal(t, "ACCEPT", management.ClientAuthAccept.String())
	require.Equal(t, "DENY", management.ClientAuthDeny.String())
	require.Equal(t, "PENDING", management.ClientAuthPending.String())
	require.Equal(t, "UNKNOWN", management.ClientAuth(4).String())
}

func TestServer_ReconnectDuringPendingAuth(t *testing.T) {
	t.Parallel()

	managementInterface, err := nettest.NewLocalListener("tcp")
	require.NoError(t, err)

	err = managementInterface.Close()
	require.NoError(t, err)

	managementServer := management.NewServer(slog.New(slog.DiscardHandler), "")
	err = managementServer.Listen(t.Context(), fmt.Sprintf("%s://%s", managementInterface.Addr().Network(), managementInterface.Addr().String()))
	require.NoError(t, err)

	t.Cleanup(managementServer.Close)

	ctx := t.Context()
	errCh := make(chan error, 1)

	// Register a pending poller that will wait for a response
	go func() {
		_, err := managementServer.AuthPendingPoller(ctx, 99, time.Second*3)
		errCh <- err
	}()

	// Connect first client, then disconnect without sending a response
	var dialer net.Dialer

	client1, err := dialer.DialContext(t.Context(), "tcp", managementInterface.Addr().String())
	require.NoError(t, err)

	client1Conn := testsuite.NewConn(client1)
	client1Conn.ExpectMessage(t, openvpn.WelcomeBanner)

	// Close the first client without responding
	require.NoError(t, client1.Close())

	// Give the server time to notice the disconnect
	time.Sleep(100 * time.Millisecond)

	// Connect a second client and send the response
	client2, err := dialer.DialContext(t.Context(), "tcp", managementInterface.Addr().String())
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = client2.Close()
	})

	client2Conn := testsuite.NewConn(client2)
	client2Conn.ExpectMessage(t, openvpn.WelcomeBanner)
	client2Conn.SendMessagef(t, "client-auth-nt 99 0")
	client2Conn.ExpectMessage(t, "SUCCESS: client-auth command succeeded")

	require.NoError(t, <-errCh)
}

func TestServer_PartialMultilineClientAuth(t *testing.T) {
	t.Parallel()

	managementInterface, err := nettest.NewLocalListener("tcp")
	require.NoError(t, err)

	err = managementInterface.Close()
	require.NoError(t, err)

	managementServer := management.NewServer(slog.New(slog.DiscardHandler), "")
	err = managementServer.Listen(t.Context(), fmt.Sprintf("%s://%s", managementInterface.Addr().Network(), managementInterface.Addr().String()))
	require.NoError(t, err)

	t.Cleanup(managementServer.Close)

	var dialer net.Dialer

	// Connect and send a partial multiline client-auth, then disconnect
	client, err := dialer.DialContext(t.Context(), "tcp", managementInterface.Addr().String())
	require.NoError(t, err)

	clientConn := testsuite.NewConn(client)
	clientConn.ExpectMessage(t, openvpn.WelcomeBanner)

	// Send client-auth without the END terminator, then close
	clientConn.SendMessagef(t, "client-auth 1 0")
	clientConn.SendMessagef(t, "push \"route 10.0.0.0 255.255.255.0\"")

	// Close without sending END — the server should handle this gracefully
	require.NoError(t, client.Close())

	// Give the server time to process
	time.Sleep(100 * time.Millisecond)

	// The server should still be able to accept new connections
	client2, err := dialer.DialContext(t.Context(), "tcp", managementInterface.Addr().String())
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = client2.Close()
	})

	client2Conn := testsuite.NewConn(client2)
	client2Conn.ExpectMessage(t, openvpn.WelcomeBanner)
	client2Conn.SendAndExpectMessage(t, "help", "SUCCESS: help")
}

func TestServer_ContextCancellation(t *testing.T) {
	t.Parallel()

	managementInterface, err := nettest.NewLocalListener("tcp")
	require.NoError(t, err)

	err = managementInterface.Close()
	require.NoError(t, err)

	managementServer := management.NewServer(slog.New(slog.DiscardHandler), "")
	err = managementServer.Listen(t.Context(), fmt.Sprintf("%s://%s", managementInterface.Addr().Network(), managementInterface.Addr().String()))
	require.NoError(t, err)

	t.Cleanup(managementServer.Close)

	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)

	go func() {
		_, err := managementServer.AuthPendingPoller(ctx, 42, time.Minute)
		errCh <- err
	}()

	// Cancel the context — the poller should return immediately
	cancel()

	err = <-errCh
	require.ErrorIs(t, err, context.Canceled)
}
