package management_test

import (
	"fmt"
	"log/slog"
	"testing"

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
		})
	}
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
