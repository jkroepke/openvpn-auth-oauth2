package testutils

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TCPTestListener(tb testing.TB) net.Listener {
	tb.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(tb, err)

	return listener
}
