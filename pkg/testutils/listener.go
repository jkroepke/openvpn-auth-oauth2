package testutils

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TCPTestListener(t *testing.T) net.Listener {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	return listener
}
