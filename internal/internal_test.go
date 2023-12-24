package internal_test

import (
	"bufio"
	"context"
	"fmt"
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

func BenchmarkFull(b *testing.B) {
	_, client, managementInterface, _, _, httpClient, shutdownFn := testutils.SetupMockEnvironment(b, config.Config{})
	defer shutdownFn()

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()

		err := client.Connect()
		if err != nil && !strings.HasSuffix(err.Error(), "EOF") {
			require.NoError(b, err)
		}
	}()

	managementInterfaceConn, err := managementInterface.Accept()
	require.NoError(b, err)

	defer managementInterfaceConn.Close()
	defer client.Shutdown()

	reader := bufio.NewReader(managementInterfaceConn)

	testutils.SendLine(b, managementInterfaceConn, ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\r\n")
	assert.Equal(b, "hold release", testutils.ReadLine(b, reader))
	testutils.SendLine(b, managementInterfaceConn, "SUCCESS: hold release succeeded\r\n")
	assert.Equal(b, "version", testutils.ReadLine(b, reader))

	testutils.SendLine(b, managementInterfaceConn, "OpenVPN Version: OpenVPN Mock\r\nManagement Interface Version: 5\r\nEND\r\n")

	time.Sleep(time.Millisecond * 100)

	var (
		request *http.Request
		resp    *http.Response
		auth    string
	)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		wg := sync.WaitGroup{}

		testutils.SendLine(b, managementInterfaceConn, fmt.Sprintf(">CLIENT:CONNECT,%d,2\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END\r\n", i))

		auth = testutils.ReadLine(b, reader)
		assert.Contains(b, auth, fmt.Sprintf("client-pending-auth %d 2 \"WEB_AUTH::", i))
		testutils.SendLine(b, managementInterfaceConn, "SUCCESS: %s command succeeded\r\n", strings.SplitN(auth, " ", 2)[0])

		authURL := strings.TrimPrefix(strings.Split(auth, `"`)[1], "WEB_AUTH::")

		request, err = http.NewRequestWithContext(context.Background(), http.MethodGet, authURL, nil)
		require.NoError(b, err)

		wg.Add(1)

		go func() {
			defer wg.Done()
			assert.Equal(b, fmt.Sprintf("client-auth-nt %d 2", i), testutils.ReadLine(b, reader))
			testutils.SendLine(b, managementInterfaceConn, "SUCCESS: client-auth command succeeded\r\n")
		}()

		resp, err = httpClient.Do(request)
		require.NoError(b, err)
		require.Equal(b, http.StatusOK, resp.StatusCode)

		wg.Wait()

		_, err = io.Copy(io.Discard, resp.Body)
		require.NoError(b, err)

		require.NoError(b, resp.Body.Close())

		testutils.SendLine(b, managementInterfaceConn, fmt.Sprintf(">CLIENT:DISCONNECT,%d\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END\r\n", i))
	}

	b.StopTimer()

	client.Shutdown()
	wg.Wait()

	b.ReportAllocs()
}
