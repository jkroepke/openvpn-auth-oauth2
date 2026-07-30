package testsuite_test

import (
	"bufio"
	"net"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/test/testsuite"
	"github.com/stretchr/testify/require"
)

func TestConnectionDiagnosticsAreLazy(t *testing.T) {
	t.Parallel()

	client, server := net.Pipe()

	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	serverDone := make(chan error, 1)

	go func() {
		reader := bufio.NewReader(server)
		if _, err := reader.ReadString('\n'); err != nil {
			serverDone <- err

			return
		}

		_, err := server.Write([]byte("response\r\n"))
		serverDone <- err
	}()

	diagnosticCalls := 0
	conn := testsuite.NewConn(client).WithLogs(func() string {
		diagnosticCalls++

		return "diagnostic logs"
	})

	conn.SendAndExpectMessage(t, "request", "response")

	require.NoError(t, <-serverDone)
	require.Zero(t, diagnosticCalls)
}
