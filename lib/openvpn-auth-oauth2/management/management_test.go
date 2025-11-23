package management_test

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
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

			client, err := net.Dial(tc.protocol, managementInterface.Addr().String())
			require.NoError(t, err)
			clientReader := bufio.NewReader(client)

			testutils.ExpectMessage(t, client, clientReader, ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info")
			testutils.SendMessagef(t, client, "")
			testutils.SendAndExpectMessage(t, client, clientReader, "hold release", "SUCCESS: hold released")
			testutils.SendAndExpectMessage(t, client, clientReader, "version", fmt.Sprintf("OpenVPN Version: openvpn-auth-oauth2 %s\nManagement Interface Version: 5\nEND", version.Version))
			testutils.SendAndExpectMessage(t, client, clientReader, "help", "SUCCESS: help")
			testutils.SendAndExpectMessage(t, client, clientReader, "unknown", "ERROR: unknown command, enter 'help' for more options")

			require.NoError(t, client.Close())

			client, err = net.Dial(tc.protocol, managementInterface.Addr().String())
			require.NoError(t, err)
			clientReader = bufio.NewReader(client)

			testutils.ExpectMessage(t, client, clientReader, ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info")
			testutils.SendAndExpectMessage(t, client, clientReader, "exit", "SUCCESS: exiting")

			client, err = net.Dial(tc.protocol, managementInterface.Addr().String())
			require.NoError(t, err)
			clientReader = bufio.NewReader(client)

			testutils.ExpectMessage(t, client, clientReader, ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info")
			testutils.SendAndExpectMessage(t, client, clientReader, "quit", "SUCCESS: exiting")

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
