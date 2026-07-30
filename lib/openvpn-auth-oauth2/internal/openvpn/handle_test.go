//go:build (darwin || linux || openbsd || freebsd) && cgo

//nolint:testpackage
package openvpn

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	internalopenvpn "github.com/jkroepke/openvpn-auth-oauth2/v2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/test/testlogger"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/test/testsuite"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/lib/openvpn-auth-oauth2/internal/c"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/nettest"
)

func TestHandlePluginUpListenFailure(t *testing.T) {
	t.Parallel()

	handle := newTestPluginHandle(t)
	handle.listenSocketAddr = "unsupported://management"

	require.Equal(t, c.OpenVPNPluginFuncError, handle.handlePluginUp())
}

//nolint:paralleltest // handleAuthUserPassVerify increments the package-level clientIDCounter.
func TestHandleAuthUserPassVerifyPendingFileWriteFailure(t *testing.T) {
	clientIDCounter.Store(0)
	t.Cleanup(func() {
		clientIDCounter.Store(0)
	})

	const clientID = uint64(1)

	handle, managementConn := newConnectedTestPluginHandle(t)
	clientContext := &ClientContext{}
	statusCh := startTestClientAuth(t, handle, managementConn, clientID, validAuthUserPassVerifyEnv(), clientContext)

	managementConn.SendMessagef(t, `client-pending-auth %d 0 "WEB_AUTH::https://example.com/auth" 300`, clientID)
	managementConn.ExpectMessage(t, "ERROR: client-pending-auth command failed")

	require.Equal(t, c.OpenVPNPluginFuncError, <-statusCh)

	pendingRespCh, err := handle.managementClient.RegisterPendingPoller(clientID)
	require.NoError(t, err)
	require.NotNil(t, pendingRespCh)

	handle.managementClient.CancelPendingPoller(clientID)
}

//nolint:paralleltest // handleAuthUserPassVerify increments the package-level clientIDCounter.
func TestHandleAuthUserPassVerifyFinalAuthFileWriteFailure(t *testing.T) {
	for _, testCase := range []struct {
		name            string
		command         string
		expectedCommand string
	}{
		{
			name:            "accept",
			command:         "client-auth-nt %d 0",
			expectedCommand: "ERROR: client-auth command failed",
		},
		{
			name:            "deny",
			command:         `client-deny %d 0 "access denied"`,
			expectedCommand: "ERROR: client-deny command failed",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			clientIDCounter.Store(0)
			t.Cleanup(func() {
				clientIDCounter.Store(0)
			})

			const clientID = uint64(1)

			testDir := t.TempDir()
			authPendingFile := filepath.Join(testDir, "auth-pending")
			authControlFile := filepath.Join(testDir, "missing", "auth-control")
			env := append(
				validAuthUserPassVerifyEnv(),
				"auth_pending_file="+authPendingFile,
				"auth_control_file="+authControlFile,
			)

			handle, managementConn := newConnectedTestPluginHandle(t)
			clientContext := &ClientContext{}
			statusCh := startTestClientAuth(t, handle, managementConn, clientID, env, clientContext)

			managementConn.SendMessagef(t, `client-pending-auth %d 0 "WEB_AUTH::https://example.com/auth" 300`, clientID)
			managementConn.ExpectMessage(t, "SUCCESS: client-pending-auth command succeeded")

			require.Equal(t, c.OpenVPNPluginFuncDeferred, <-statusCh)

			managementConn.SendMessagef(t, testCase.command, clientID)
			managementConn.ExpectMessage(t, testCase.expectedCommand)
			require.NoFileExists(t, authControlFile)
		})
	}
}

//nolint:paralleltest // handleAuthUserPassVerify increments the package-level clientIDCounter.
func TestHandleAuthUserPassVerifyCancelsPendingPoller(t *testing.T) {
	clientIDCounter.Store(0)
	t.Cleanup(func() {
		clientIDCounter.Store(0)
	})

	const clientID = uint64(1)

	authPendingFile := filepath.Join(t.TempDir(), "auth-pending")
	env := append(validAuthUserPassVerifyEnv(), "auth_pending_file="+authPendingFile)

	handle, managementConn := newConnectedTestPluginHandle(t)
	logger := testlogger.New()
	handle.logger = logger.Logger()

	clientContext := &ClientContext{}
	statusCh := startTestClientAuth(t, handle, managementConn, clientID, env, clientContext)

	managementConn.SendMessagef(t, `client-pending-auth %d 0 "WEB_AUTH::https://example.com/auth" 300`, clientID)
	managementConn.ExpectMessage(t, "SUCCESS: client-pending-auth command succeeded")

	require.Equal(t, c.OpenVPNPluginFuncDeferred, <-statusCh)

	handle.cancel()

	require.Eventually(t, func() bool {
		return strings.Contains(logger.String(), "poll deferred auth state")
	}, time.Second, 10*time.Millisecond)
	require.Contains(t, logger.String(), "context canceled")

	pendingRespCh, err := handle.managementClient.RegisterPendingPoller(clientID)
	require.NoError(t, err)
	require.NotNil(t, pendingRespCh)

	handle.managementClient.CancelPendingPoller(clientID)
}

func newConnectedTestPluginHandle(t *testing.T) (*PluginHandle, *testsuite.Conn) {
	t.Helper()

	managementInterface, err := nettest.NewLocalListener("tcp")
	require.NoError(t, err)

	managementAddr := managementInterface.Addr()

	require.NoError(t, managementInterface.Close())

	handle := newTestPluginHandle(t)
	handle.listenSocketAddr = fmt.Sprintf("%s://%s", managementAddr.Network(), managementAddr.String())

	require.Equal(t, c.OpenVPNPluginFuncSuccess, handle.handlePluginUp())
	t.Cleanup(handle.managementClient.Close)

	var dialer net.Dialer

	clientConn, err := dialer.DialContext(t.Context(), managementAddr.Network(), managementAddr.String())
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = clientConn.Close()
	})

	managementConn := testsuite.NewConn(clientConn)
	managementConn.ExpectMessage(t, internalopenvpn.WelcomeBanner)

	return handle, managementConn
}

func startTestClientAuth(
	t *testing.T,
	handle *PluginHandle,
	managementConn *testsuite.Conn,
	clientID uint64,
	env []string,
	clientContext *ClientContext,
) <-chan c.OpenVPNPluginFuncStatus {
	t.Helper()

	envp := newTestEnvp(t, env)
	statusCh := make(chan c.OpenVPNPluginFuncStatus, 1)

	go func() {
		statusCh <- handle.handleAuthUserPassVerify(envp, clientContext)
	}()

	require.Regexp(t, fmt.Sprintf(`^>CLIENT:CONNECT,%d,\d+$`, clientID), managementConn.ReadLine(t))

	for line := managementConn.ReadLine(t); line != ">CLIENT:ENV,END"; line = managementConn.ReadLine(t) {
		require.Contains(t, line, ">CLIENT:ENV,")
	}

	return statusCh
}
