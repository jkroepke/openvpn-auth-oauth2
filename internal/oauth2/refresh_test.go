package oauth2_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/storage"
	"github.com/jkroepke/openvpn-auth-oauth2/pkg/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefreshReAuth(t *testing.T) {
	t.Parallel()

	logger := testutils.NewTestLogger()

	managementInterface, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer managementInterface.Close()

	clientListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer clientListener.Close()

	resourceServer, clientCredentials, err := testutils.SetupResourceServer(clientListener)
	require.NoError(t, err)

	defer resourceServer.Close()

	resourceServerURL, err := url.Parse(resourceServer.URL)
	require.NoError(t, err)

	conf := config.Config{
		HTTP: config.HTTP{
			BaseURL:          &url.URL{Scheme: "http", Host: clientListener.Addr().String()},
			Secret:           testutils.HTTPSecret,
			CallbackTemplate: config.Defaults.HTTP.CallbackTemplate,
		},
		OpenVpn: config.OpenVpn{
			Addr:   &url.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()},
			Bypass: config.OpenVpnBypass{CommonNames: make([]string, 0)},
		},
		OAuth2: config.OAuth2{
			Issuer:    resourceServerURL,
			Provider:  generic.Name,
			Client:    clientCredentials,
			Endpoints: config.OAuth2Endpoints{},
			Refresh:   config.OAuth2Refresh{Enabled: true},
		},
	}

	storageClient := storage.New(time.Hour)
	provider := oauth2.New(logger, conf, storageClient)
	client := openvpn.NewClient(logger, conf, provider)

	require.NoError(t, provider.Discover(client))

	httpClientListener := httptest.NewUnstartedServer(provider.Handler())
	httpClientListener.Listener.Close()
	httpClientListener.Listener = clientListener
	httpClientListener.Start()

	defer httpClientListener.Close()

	httpClient := httpClientListener.Client()

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()

		err := client.Connect()
		if err != nil && !strings.HasSuffix(err.Error(), "EOF") {
			require.NoError(t, err)
		}
	}()

	managementInterfaceConn, err := managementInterface.Accept()
	require.NoError(t, err)

	defer managementInterfaceConn.Close()
	defer client.Shutdown()

	reader := bufio.NewReader(managementInterfaceConn)
	testutils.SendLine(t, managementInterfaceConn, ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\r\n")
	assert.Equal(t, "hold release", testutils.ReadLine(t, reader))
	testutils.SendLine(t, managementInterfaceConn, "SUCCESS: hold release succeeded\r\n")
	assert.Equal(t, "version", testutils.ReadLine(t, reader))

	testutils.SendLine(t, managementInterfaceConn, "OpenVPN Version: OpenVPN Mock\r\nManagement Interface Version: 5\r\nEND\r\n")

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	httpClient.Jar = jar

	time.Sleep(time.Millisecond * 100)

	testutils.SendLine(t, managementInterfaceConn, ">CLIENT:CONNECT,1,2\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END\r\n")

	auth := testutils.ReadLine(t, reader)
	assert.Contains(t, auth, "client-pending-auth 1 2 \"WEB_AUTH::")
	testutils.SendLine(t, managementInterfaceConn, "SUCCESS: %s command succeeded\r\n", strings.SplitN(auth, " ", 2)[0])

	authURL := strings.TrimPrefix(strings.Split(auth, `"`)[1], "WEB_AUTH::")

	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, authURL, nil)
	require.NoError(t, err)

	wg.Add(1)

	go func() {
		defer wg.Done()
		assert.Equal(t, "client-auth-nt 1 2", testutils.ReadLine(t, reader))
		testutils.SendLine(t, managementInterfaceConn, "SUCCESS: client-auth command succeeded\r\n")
	}()

	resp, err := httpClient.Do(request)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)

	_ = resp.Body.Close()

	// Testing ReAuth
	testutils.SendLine(t, managementInterfaceConn, ">CLIENT:REAUTH,1,3\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END\r\n")
	assert.Equal(t, "client-auth-nt 1 3", testutils.ReadLine(t, reader))
	testutils.SendLine(t, managementInterfaceConn, "SUCCESS: client-auth command succeeded\r\n")

	// Test Disconnect
	testutils.SendLine(t, managementInterfaceConn, ">CLIENT:DISCONNECT,1\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END\r\n")

	// Test ReAuth after DC
	testutils.SendLine(t, managementInterfaceConn, ">CLIENT:REAUTH,1,3\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END\r\n")

	assert.Contains(t, auth, "client-pending-auth 1 2 \"WEB_AUTH::")
	testutils.SendLine(t, managementInterfaceConn, "SUCCESS: %s command succeeded\r\n", strings.SplitN(auth, " ", 2)[0])

	client.Shutdown()
	wg.Wait()
}
