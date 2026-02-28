package testsuite

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/nettest"
)

func (s *Suite) CreateTCPListener(tb testing.TB) net.Listener {
	tb.Helper()

	listener, err := nettest.NewLocalListener("tcp")
	require.NoError(tb, err)

	return listener
}

func (s *Suite) CreateHTTPTestServer(tb testing.TB, httpHandler http.Handler) *httptest.Server {
	tb.Helper()

	httpServer := httptest.NewUnstartedServer(httpHandler)
	require.NoError(tb, httpServer.Listener.Close())

	httpServer.Listener = s.CreateTCPListener(tb)
	httpServer.Start()
	tb.Cleanup(httpServer.Close)

	return httpServer
}
