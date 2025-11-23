//nolint:testpackage
package openvpn

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/httphandler"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/tokenstorage"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/c"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/util/testutil"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/nettest"
)

func TestPlugin(t *testing.T) {
	t.Parallel()

	unixSocket, err := nettest.LocalPath()
	require.NoError(t, err)

	passwordFile, err := os.CreateTemp(t.TempDir(), "openvpn-auth-oauth2-test-")
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = passwordFile.Close()
	})

	_, err = passwordFile.WriteString("password")
	require.NoError(t, err)

	argv, cStrings := testutil.CreateCStringArray([]string{"openvpn-auth-oauth2", "unix://" + unixSocket, passwordFile.Name()})

	openArgs := &c.OpenVPNPluginArgsOpenIn{
		Callbacks: testutil.Callbacks(),
		Argv:      argv,
	}
	openRet := &c.OpenVPNPluginArgsOpenReturn{}

	status := PluginOpenV3(PluginStructVerMin, openArgs, openRet)
	require.Equal(t, c.OpenVPNPluginFuncSuccess, status)

	t.Cleanup(func() {
		PluginCloseV1(
			openRet.Handle)
	})

	require.Equal(t, PluginTypeMask, int(openRet.TypeMask))
	require.NotNil(t, openRet.Handle)
	require.NotNil(t, openRet.Handle.Value())

	handle, ok := openRet.Handle.Value().(*PluginHandle)
	require.True(t, ok)

	require.NotNil(t, handle.ctx)
	require.Equal(t, handle.listenSocketAddr, "unix://"+unixSocket)
	require.NotNil(t, handle.logger)
	require.NotNil(t, handle.managementClient)

	// PluginFuncV3

	args := &c.OpenVPNPluginArgsFuncIn{
		Handle: openRet.Handle,
		Argv:   argv,
		Type:   c.OpenVPNPluginUp,
	}
	ret := &c.OpenVPNPluginArgsFuncReturn{}

	status = PluginFuncV3(PluginStructVerMin, args, ret)
	require.Equal(t, c.OpenVPNPluginFuncSuccess, status)

	logger := testutils.NewTestLogger()

	// clientListener must not be closed, because it is used by the httpClientListener.
	clientListener, err := nettest.NewLocalListener("tcp")
	require.NoError(t, err)

	_, resourceServerURL, clientCredentials, err := testutils.SetupResourceServer(t, clientListener, logger.Logger, nil)
	require.NoError(t, err)

	conf := config.Defaults
	conf.OpenVPN.Addr = types.URL{URL: &url.URL{Scheme: "unix", Path: unixSocket}}
	conf.OpenVPN.Password = "password"
	conf.OAuth2.Refresh.Enabled = true
	conf.OAuth2.Refresh.Secret = testutils.Secret
	conf.OAuth2.Refresh.UseSessionID = true
	conf.HTTP.BaseURL = types.URL{URL: &url.URL{Scheme: "http", Host: clientListener.Addr().String()}}
	conf.HTTP.Secret = testutils.Secret
	conf.OAuth2.Issuer = resourceServerURL
	conf.OAuth2.Nonce = true                                  // enable nonce for mock testing
	conf.OAuth2.RefreshNonce = config.OAuth2RefreshNonceEmpty // use empty nonce for the token refresh to avoid mock issues.
	conf.OAuth2.Client.ID = clientCredentials.ID
	conf.OAuth2.Client.Secret = clientCredentials.Secret
	conf.OAuth2.Refresh.Expires = time.Hour

	tokenStorage := tokenstorage.NewInMemory(testutils.Secret, time.Hour)
	oAuth2Client, openVPNClient := testutils.SetupOpenVPNOAuth2Clients(t.Context(), t, conf, logger.Logger, http.DefaultClient, tokenStorage)

	httpHandler := httphandler.New(conf, oAuth2Client)
	httpClientListener := httptest.NewUnstartedServer(httpHandler)
	require.NoError(t, httpClientListener.Listener.Close())

	httpClientListener.Listener = clientListener
	httpClientListener.Start()
	t.Cleanup(httpClientListener.Close)

	errOpenVPNClientCh := make(chan error, 1)

	go func(errCh chan<- error) {
		errCh <- openVPNClient.Connect(t.Context())
	}(errOpenVPNClientCh)

	select {
	case err := <-errOpenVPNClientCh:
		require.NoError(t, err)
	default:
	}

	time.Sleep(50 * time.Millisecond)

	clientContext := PluginClientConstructorV1(openRet.Handle)
	require.NotNil(t, clientContext)

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

	// PluginFuncV3 - OpenVPNPluginAuthUserPassVerify
	envp, cStrings := testutil.CreateCStringArray([]string{
		"n_clients=0",
		"password=",
		"session_id=SESSIONID",
		"untrusted_port=17016",
		"untrusted_ip=192.168.65.1",
		"common_name=user@example.com",
		"IV_SSO=webauth,crtext",
		"username=",
		"session_state=Initial",
		"auth_pending_file=" + authPendingFile.Name(),
		"auth_control_file=" + authControlFile.Name(),
	})

	t.Cleanup(func() {
		testutil.FreeCStringArray(envp, cStrings)
	})

	args = &c.OpenVPNPluginArgsFuncIn{
		Handle:           openRet.Handle,
		Argv:             argv,
		Envp:             envp,
		Type:             c.OpenVPNPluginAuthUserPassVerify,
		PerClientContext: unsafe.Pointer(clientContext),
	}
	ret = &c.OpenVPNPluginArgsFuncReturn{}

	status = PluginFuncV3(PluginStructVerMin, args, ret)
	require.Equal(t, c.OpenVPNPluginFuncDeferred, status)

	data, err := os.ReadFile(authPendingFile.Name())
	require.NoError(t, err)
	require.Contains(t, string(data), "180\nwebauth\nWEB_AUTH::http://")

	authURL := strings.TrimSpace(strings.SplitN(string(data), "\n", 3)[2][10:])

	request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, authURL, nil)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Jar:     jar,
	}

	var resp *http.Response

	wg := sync.WaitGroup{}
	wg.Go(func() {
		resp, err = httpClient.Do(request) //nolint:bodyclose
	})

	wg.Wait()

	require.NoError(t, err)

	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode, logger.String())

	data, err = os.ReadFile(authControlFile.Name())
	require.NoError(t, err)
	require.Equal(t, "1", string(data))

	// PluginFuncV3 - OpenVPNPluginClientConnectV2
	args.Type = c.OpenVPNPluginClientConnectV2

	var returnList *c.OpenVPNPluginStringList

	ret.ReturnList = &returnList

	status = PluginFuncV3(PluginStructVerMin, args, ret)
	require.Equal(t, c.OpenVPNPluginFuncSuccess, status)

	require.Equal(t, "config", c.GoString(returnList.Name))
	require.Equal(t, "push \"auth-token-user dXNlckBleGFtcGxlLmNvbQ==\"", c.GoString(returnList.Value))

	// PluginFuncV3 - OpenVPNPluginClientDisconnect
	args.Type = c.OpenVPNPluginClientDisconnect

	status = PluginFuncV3(PluginStructVerMin, args, ret)
	require.Equal(t, c.OpenVPNPluginFuncSuccess, status)

	// PluginClientDestructorV1
	PluginClientDestructorV1(args.Handle, clientContext)
}

func TestPluginOpenV3_InvalidArgs(t *testing.T) {
	t.Parallel()

	status := PluginOpenV3(0, nil, nil)
	require.Equal(t, c.OpenVPNPluginFuncError, status)
}

func TestPluginFuncV3_InvalidArgs(t *testing.T) {
	t.Parallel()

	status := PluginFuncV3(0, nil, nil)
	require.Equal(t, c.OpenVPNPluginFuncError, status)
}
