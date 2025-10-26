package client_test

import (
	"os"
	"slices"
	"strings"
	"testing"
	"testing/synctest"

	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/client"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/management"
	"github.com/stretchr/testify/require"
)

func TestNewClient_Full(t *testing.T) {
	t.Parallel()

	vpnClient, err := client.NewClient(12345, map[string]string{
		"auth_failed_reason_file": "/tmp/auth_failed_reason_file",
		"auth_pending_file":       "/tmp/auth_pending_file",
		"auth_control_file":       "/tmp/auth_control_file",
		"username":                "testuser",
		"password":                "testpassword",
		"common_name":             "testuser",
		"session_id":              "abcdef123456",
		"untrusted_ip":            "127.0.0.1",
		"untrusted_port":          "1194",
	})
	require.NoError(t, err)

	require.Equal(t, uint64(12345), vpnClient.ClientID)
	require.Equal(t, "/tmp/auth_failed_reason_file", vpnClient.AuthFailedReasonFile)
	require.Equal(t, "/tmp/auth_pending_file", vpnClient.AuthPendingFile)
	require.Equal(t, "/tmp/auth_control_file", vpnClient.AuthControlFile)

	synctest.Test(t, func(t *testing.T) {
		message := strings.Split(vpnClient.GetConnectMessage(), "\r\n")

		slices.Sort(message)

		require.Equal(t, []string{
			">CLIENT:CONNECT,12345,946684800",
			">CLIENT:ENV,END",
			">CLIENT:ENV,common_name=testuser",
			">CLIENT:ENV,password=testpassword",
			">CLIENT:ENV,session_id=abcdef123456",
			">CLIENT:ENV,untrusted_ip=127.0.0.1",
			">CLIENT:ENV,untrusted_port=1194",
			">CLIENT:ENV,username=testuser",
		}, message)

		message = strings.Split(vpnClient.GetDisconnectMessage(), "\r\n")

		slices.Sort(message)

		require.Equal(t, []string{
			">CLIENT:DISCONNECT,12345",
			">CLIENT:ENV,END",
			">CLIENT:ENV,common_name=testuser",
			">CLIENT:ENV,password=testpassword",
			">CLIENT:ENV,session_id=abcdef123456",
			">CLIENT:ENV,untrusted_ip=127.0.0.1",
			">CLIENT:ENV,untrusted_port=1194",
			">CLIENT:ENV,username=testuser",
		}, message)
	})
}

func TestNewClient_ClientID(t *testing.T) {
	var err error

	_, err = client.NewClient(1, map[string]string{})
	require.NoError(t, err)

	_, err = client.NewClient(10, map[string]string{})
	require.NoError(t, err)

	_, err = client.NewClient(100, map[string]string{})
	require.NoError(t, err)

	_, err = client.NewClient(1000, map[string]string{})
	require.NoError(t, err)

	_, err = client.NewClient(10000, map[string]string{})
	require.NoError(t, err)

	_, err = client.NewClient(100000, map[string]string{})
	require.NoError(t, err)

	_, err = client.NewClient(1000000, map[string]string{})
	require.NoError(t, err)
}

func TestClient_WriteToAuthFile(t *testing.T) {
	t.Parallel()

	t.Run("OK", func(t *testing.T) {
		t.Parallel()

		authControlFile, err := os.CreateTemp(t.TempDir(), "auth_control_file")
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, authControlFile.Close())
		})

		vpnClient, err := client.NewClient(12345, map[string]string{
			"auth_control_file": authControlFile.Name(),
		})
		require.NoError(t, err)

		err = vpnClient.WriteToAuthFile("1")
		require.NoError(t, err)

		data, err := os.ReadFile(authControlFile.Name())
		require.NoError(t, err)
		require.Equal(t, "1", string(data))
	})

	t.Run("AuthControlFileNotSet", func(t *testing.T) {
		t.Parallel()

		vpnClient, err := client.NewClient(12345, map[string]string{})
		require.NoError(t, err)

		err = vpnClient.WriteToAuthFile("1")
		require.ErrorIs(t, err, client.ErrAuthControlFileNotSet)
	})

	t.Run("WriteError", func(t *testing.T) {
		t.Parallel()

		vpnClient, err := client.NewClient(12345, map[string]string{
			"auth_control_file": "/non/existent/path/auth_control_file",
		})
		require.NoError(t, err)

		err = vpnClient.WriteToAuthFile("1")
		require.Error(t, err)
	})
}

func TestClient_WriteAuthPending(t *testing.T) {
	t.Parallel()

	t.Run("OK", func(t *testing.T) {
		t.Parallel()

		authControlFile, err := os.CreateTemp(t.TempDir(), "auth_control_file")
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, authControlFile.Close())
		})

		authPendingFile, err := os.CreateTemp(t.TempDir(), "auth_pending_file")
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, authPendingFile.Close())
		})

		vpnClient, err := client.NewClient(12345, map[string]string{
			"auth_pending_file": authPendingFile.Name(),
			"auth_control_file": authControlFile.Name(),
		})
		require.NoError(t, err)

		err = vpnClient.WriteAuthPending(&management.Response{
			Message: "TEST",
			Timeout: "300",
		})
		require.NoError(t, err)

		data, err := os.ReadFile(authPendingFile.Name())
		require.NoError(t, err)
		require.Equal(t, "300\nwebauth\nTEST\n", string(data))

		data, err = os.ReadFile(authControlFile.Name())
		require.NoError(t, err)
		require.Equal(t, "2", string(data))
	})

	t.Run("WriteError", func(t *testing.T) {
		t.Parallel()

		vpnClient, err := client.NewClient(12345, map[string]string{
			"auth_pending_file": "/non/existent/path/auth_pending_file",
		})
		require.NoError(t, err)

		err = vpnClient.WriteAuthPending(&management.Response{
			Message: "TEST",
			Timeout: "300",
		})
		require.Error(t, err)
	})

	t.Run("AuthPendingFileNotSet", func(t *testing.T) {
		t.Parallel()

		vpnClient, err := client.NewClient(12345, map[string]string{})
		require.NoError(t, err)

		err = vpnClient.WriteAuthPending(&management.Response{
			Message: "TEST",
			Timeout: "300",
		})
		require.ErrorIs(t, err, client.ErrAuthPendingFileNotSet)
	})
}

func BenchmarkClient_GetConnectMessage(b *testing.B) {
	vpnClient, err := client.NewClient(12345, map[string]string{
		"auth_failed_reason_file": "/tmp/auth_failed_reason_file",
		"auth_pending_file":       "/tmp/auth_pending_file",
		"auth_control_file":       "/tmp/auth_control_file",
		"username":                "testuser",
		"password":                "testpassword",
		"common_name":             "testuser",
		"session_id":              "abcdef123456",
		"untrusted_ip":            "127.0.0.1",
		"untrusted_port":          "1194",
	})
	require.NoError(b, err)

	b.ResetTimer()

	for b.Loop() {
		_ = vpnClient.GetConnectMessage()
	}

	b.ReportAllocs()
}

func BenchmarkClient_GetDisconnectMessage(b *testing.B) {
	vpnClient, err := client.NewClient(12345, map[string]string{
		"auth_failed_reason_file": "/tmp/auth_failed_reason_file",
		"auth_pending_file":       "/tmp/auth_pending_file",
		"auth_control_file":       "/tmp/auth_control_file",
		"username":                "testuser",
		"password":                "testpassword",
		"common_name":             "testuser",
		"session_id":              "abcdef123456",
		"untrusted_ip":            "127.0.0.1",
		"untrusted_port":          "1194",
	})
	require.NoError(b, err)

	b.ResetTimer()

	for b.Loop() {
		_ = vpnClient.GetDisconnectMessage()
	}

	b.ReportAllocs()
}
