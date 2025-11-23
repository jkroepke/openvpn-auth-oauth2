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

			client, err := net.Dial(tc.protocol, managementInterface.Addr().String())
			require.NoError(t, err)
			clientReader := bufio.NewReader(client)

			testutils.ExpectMessage(t, client, clientReader, openvpn.WelcomeBanner)
			testutils.SendMessagef(t, client, "")
			testutils.SendAndExpectMessage(t, client, clientReader, "hold release", "SUCCESS: hold released")
			testutils.SendAndExpectMessage(t, client, clientReader, "version", fmt.Sprintf("OpenVPN Version: openvpn-auth-oauth2 %s\nManagement Interface Version: 5\nEND", version.Version))
			testutils.SendAndExpectMessage(t, client, clientReader, "help", "SUCCESS: help")
			testutils.SendAndExpectMessage(t, client, clientReader, "unknown", "ERROR: unknown command, enter 'help' for more options")

			require.NoError(t, client.Close())

			client, err = net.Dial(tc.protocol, managementInterface.Addr().String())
			require.NoError(t, err)
			clientReader = bufio.NewReader(client)

			testutils.ExpectMessage(t, client, clientReader, openvpn.WelcomeBanner)
			testutils.SendAndExpectMessage(t, client, clientReader, "exit", "SUCCESS: exiting")

			client, err = net.Dial(tc.protocol, managementInterface.Addr().String())
			require.NoError(t, err)
			clientReader = bufio.NewReader(client)

			testutils.ExpectMessage(t, client, clientReader, openvpn.WelcomeBanner)
			testutils.SendAndExpectMessage(t, client, clientReader, "quit", "SUCCESS: exiting")

			client, err = net.Dial(tc.protocol, managementInterface.Addr().String())
			require.NoError(t, err)
			require.NoError(t, client.Close())
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

func TestServer_Listen_Password(t *testing.T) {
	t.Parallel()

	managementInterface, err := nettest.NewLocalListener("tcp")
	require.NoError(t, err)

	err = managementInterface.Close()
	require.NoError(t, err)

	managementServer := management.NewServer(slog.New(slog.DiscardHandler), testutils.Password)
	err = managementServer.Listen(t.Context(), fmt.Sprintf("%s://%s", managementInterface.Addr().Network(), managementInterface.Addr().String()))
	require.NoError(t, err)

	t.Cleanup(managementServer.Close)

	client, err := net.Dial("tcp", managementInterface.Addr().String())
	require.NoError(t, err)
	clientReader := bufio.NewReader(client)

	resp, err := clientReader.ReadString(':')
	require.NoError(t, err)
	require.Equal(t, "ENTER PASSWORD:", resp)

	testutils.SendMessagef(t, client, testutils.Password)
	testutils.ExpectMessage(t, client, clientReader, "SUCCESS: password is correct")
	testutils.ExpectMessage(t, client, clientReader, openvpn.WelcomeBanner)
	testutils.SendMessagef(t, client, "quit")
}
