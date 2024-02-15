package oauth2_test

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/pkg/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefreshReAuth(t *testing.T) {
	t.Parallel()

	_, client, managementInterface, _, _, httpClient, _, shutdownFn := testutils.SetupMockEnvironment(t, config.Config{
		OAuth2: config.OAuth2{
			Refresh: config.OAuth2Refresh{Enabled: true},
		},
	})
	defer shutdownFn()

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()

		err := client.Connect()
		if err != nil && !strings.HasSuffix(err.Error(), "EOF") {
			require.NoError(t, err) //nolint:testifylint
		}
	}()

	managementInterfaceConn, err := managementInterface.Accept()
	require.NoError(t, err)

	defer managementInterfaceConn.Close()

	reader := bufio.NewReader(managementInterfaceConn)

	testutils.ExpectVersionAndReleaseHold(t, managementInterfaceConn, reader)

	time.Sleep(time.Millisecond * 100)

	testutils.SendMessage(t, managementInterfaceConn, ">CLIENT:CONNECT,1,2\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END")

	auth := testutils.ReadLine(t, managementInterfaceConn, reader)
	assert.Contains(t, auth, "client-pending-auth 1 2 \"WEB_AUTH::")
	testutils.SendMessage(t, managementInterfaceConn, "SUCCESS: %s command succeeded\r\n", strings.SplitN(auth, " ", 2)[0])

	authURL := strings.TrimPrefix(strings.Split(auth, `"`)[1], "WEB_AUTH::")

	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, authURL, nil)
	require.NoError(t, err)

	wg.Add(1)

	go func() {
		defer wg.Done()

		testutils.ExpectMessage(t, managementInterfaceConn, reader, "client-auth-nt 1 2")
		testutils.SendMessage(t, managementInterfaceConn, "SUCCESS: client-auth command succeeded")
	}()

	resp, err := httpClient.Do(request)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)

	_ = resp.Body.Close()

	// Testing ReAuth
	testutils.SendAndExpectMessage(t, managementInterfaceConn, reader,
		">CLIENT:REAUTH,1,3\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END",
		"client-auth-nt 1 3",
	)
	testutils.SendMessage(t, managementInterfaceConn, "SUCCESS: client-auth command succeeded")

	// Test Disconnect
	testutils.SendMessage(t, managementInterfaceConn, ">CLIENT:DISCONNECT,1\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END")

	// Test ReAuth after DC
	testutils.SendMessage(t, managementInterfaceConn, ">CLIENT:REAUTH,1,3\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END")

	assert.Contains(t, testutils.ReadLine(t, managementInterfaceConn, reader), "client-pending-auth 1 3 \"WEB_AUTH::")
	testutils.SendMessage(t, managementInterfaceConn, "SUCCESS: %s command succeeded\r\n", strings.SplitN(auth, " ", 2)[0])

	time.Sleep(time.Millisecond * 50)

	client.Shutdown()
	wg.Wait()
}
