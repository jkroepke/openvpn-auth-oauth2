//go:build (darwin || linux || openbsd || freebsd) && cgo

//nolint:testpackage
package openvpn

import (
	"fmt"
	"net"
	"testing"

	internalopenvpn "github.com/jkroepke/openvpn-auth-oauth2/v2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/test/testsuite"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/lib/openvpn-auth-oauth2/internal/c"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/nettest"
)

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
