package management_test

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
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

			var dialer net.Dialer

			client, err := dialer.DialContext(t.Context(), tc.protocol, managementInterface.Addr().String())
			require.NoError(t, err)

			clientReader := bufio.NewReader(client)

			testutils.ExpectMessage(t, client, clientReader, openvpn.WelcomeBanner)
			testutils.SendMessagef(t, client, "")
			testutils.SendAndExpectMessage(t, client, clientReader, "hold release", "SUCCESS: hold released")
			testutils.SendAndExpectMessage(t, client, clientReader, "version", fmt.Sprintf("OpenVPN Version: openvpn-auth-oauth2 %s\nManagement Interface Version: 5\nEND", version.Version))
			testutils.SendAndExpectMessage(t, client, clientReader, "help", "SUCCESS: help")
			testutils.SendAndExpectMessage(t, client, clientReader, "unknown", "ERROR: unknown command, enter 'help' for more options")

			require.NoError(t, client.Close())

			client, err = dialer.DialContext(t.Context(), tc.protocol, managementInterface.Addr().String())
			require.NoError(t, err)

			clientReader = bufio.NewReader(client)

			testutils.ExpectMessage(t, client, clientReader, openvpn.WelcomeBanner)
			testutils.SendAndExpectMessage(t, client, clientReader, "exit", "SUCCESS: exiting")

			client, err = dialer.DialContext(t.Context(), tc.protocol, managementInterface.Addr().String())
			require.NoError(t, err)

			clientReader = bufio.NewReader(client)

			testutils.ExpectMessage(t, client, clientReader, openvpn.WelcomeBanner)
			testutils.SendAndExpectMessage(t, client, clientReader, "quit", "SUCCESS: exiting")

			client, err = dialer.DialContext(t.Context(), tc.protocol, managementInterface.Addr().String())
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

	var dialer net.Dialer

	client, err := dialer.DialContext(t.Context(), "tcp", managementInterface.Addr().String())
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

func TestServer_AuthPendingPoller(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		command string
		testFn  func(t *testing.T, response *management.Response)
	}{
		{
			name:    "client-auth-nt",
			command: "client-auth-nt 1 0",
			testFn: func(t *testing.T, response *management.Response) {
				t.Helper()

				require.Equal(t, uint32(1), response.ClientID)
				require.Equal(t, management.ClientAuthAccept, response.ClientAuth)
			},
		},
		{
			name:    "client-auth",
			command: "client-auth 2 0\r\npush \"reneg-sec 0\"\r\nEND",
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
			testFn: func(t *testing.T, response *management.Response) {
				t.Helper()

				require.Equal(t, uint32(4), response.ClientID)
				require.Equal(t, management.ClientAuthPending, response.ClientAuth)
				require.Equal(t, "WEB_AUTH::https://sso.example.com/auth?session=xyz", response.Message)
				require.Equal(t, "300", response.Timeout)
			},
		},
		{
			name:    "client-pending-auth invalid",
			command: "client-pending-auth 4 0 \"WEB_AUTH::https://sso.example.com/auth?session=xyz\"",
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

			if tc.command != "invalid" {
				clientID, err = strconv.ParseUint(strings.Split(tc.command, " ")[1], 10, 64)
				require.NoError(t, err)
			}

			go func() {
				response, err := managementServer.AuthPendingPoller(clientID, time.Second*5)

				errCh <- err

				responseCh <- response
			}()

			var dialer net.Dialer

			client, err := dialer.DialContext(t.Context(), "tcp", managementInterface.Addr().String())
			require.NoError(t, err)

			clientReader := bufio.NewReader(client)

			testutils.ExpectMessage(t, client, clientReader, openvpn.WelcomeBanner)
			testutils.SendMessagef(t, client, tc.command)

			if tc.command == "invalid" {
				testutils.ExpectMessage(t, client, clientReader, "ERROR: unknown command, enter 'help' for more options")

				return
			}

			testutils.ExpectMessage(t, client, clientReader, fmt.Sprintf("SUCCESS: %s command succeeded", strings.TrimSuffix(strings.Split(tc.command, " ")[0], "-nt")))

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

func TestClientAuth_String(t *testing.T) {
	t.Parallel()

	require.Equal(t, "ACCEPT", management.ClientAuthAccept.String())
	require.Equal(t, "DENY", management.ClientAuthDeny.String())
	require.Equal(t, "PENDING", management.ClientAuthPending.String())
	require.Equal(t, "UNKNOWN", management.ClientAuth(4).String())
}
