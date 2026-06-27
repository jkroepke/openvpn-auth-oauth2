//go:build (darwin || linux || openbsd || freebsd) && cgo

//nolint:testpackage
package openvpn

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/httphandler"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/test/testsuite"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/c"
	"github.com/jkroepke/openvpn-auth-oauth2/lib/openvpn-auth-oauth2/util/testutil"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/nettest"
)

func TestPlugin(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		conf config.Config
	}{
		{
			name: "default config",
			conf: config.Defaults,
		},
		{
			name: "with refresh",
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Refresh.Enabled = true
				conf.OAuth2.Refresh.Secret = testsuite.Secret
				conf.OAuth2.Refresh.UseSessionID = true

				return conf
			}(),
		},
		{
			name: "without auth token user",
			conf: func() config.Config {
				conf := config.Defaults
				conf.OAuth2.Refresh.Enabled = false
				conf.OpenVPN.AuthTokenUser = false

				return conf
			}(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
				PluginCloseV1(openRet.Handle)
			})

			require.Equal(t, PluginTypeMask, int(openRet.TypeMask))
			require.NotZero(t, openRet.Handle)
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

			// clientListener must not be closed, because it is used by the httpClientListener.
			clientListener, err := nettest.NewLocalListener("tcp")
			require.NoError(t, err)

			tc.conf.OpenVPN.Addr = types.URL{URL: &url.URL{Scheme: "unix", Path: unixSocket}}
			tc.conf.OpenVPN.Password = "password"
			tc.conf.OAuth2.OpenVPNUsername = "oauth2TokenClaims." + testsuite.SubjectClaim

			suite := testsuite.New(tc.conf)
			suite.SetupOIDCServer(t, clientListener, nil)
			tc.conf = suite.GetConfig()

			oAuth2Client, openVPNClient := suite.SetupOpenVPNOAuth2Clients(t.Context(), t, nil)

			httpHandler := httphandler.New(tc.conf, oAuth2Client)
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

			clientContextPtr := PluginClientConstructorV1(openRet.Handle)
			require.NotNil(t, clientContextPtr)

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
				PerClientContext: clientContextPtr,
			}
			ret = &c.OpenVPNPluginArgsFuncReturn{}

			status = PluginFuncV3(PluginStructVerMin, args, ret)
			require.Equal(t, c.OpenVPNPluginFuncDeferred, status)

			data, err := os.ReadFile(authPendingFile.Name())
			require.NoError(t, err)
			require.Contains(t, string(data), "180\nwebauth\nWEB_AUTH::http://")

			authURL := strings.TrimSpace(strings.SplitN(string(data), "\n", 3)[2][10:])

			jar, err := cookiejar.New(nil)
			require.NoError(t, err)

			httpClient := &http.Client{
				Timeout: 5 * time.Second,
				Jar:     jar,
			}

			var resp *http.Response

			wg := sync.WaitGroup{}
			wg.Go(func() {
				resp, _, err = testsuite.DoHTTPRequest(t, httpClient, "", http.MethodGet, authURL, nil, http.NoBody) //nolint:bodyclose
			})

			wg.Wait()

			require.NoError(t, err)

			require.Equal(t, http.StatusOK, resp.StatusCode, suite.Logs())

			data, err = os.ReadFile(authControlFile.Name())
			require.NoError(t, err)
			require.Equal(t, "1", string(data))

			// PluginFuncV3 - OpenVPNPluginClientConnectV2
			args.Type = c.OpenVPNPluginClientConnectV2

			var returnList *c.OpenVPNPluginStringList

			ret.ReturnList = &returnList

			status = PluginFuncV3(PluginStructVerMin, args, ret)
			require.Equal(t, c.OpenVPNPluginFuncSuccess, status)

			if tc.conf.OpenVPN.AuthTokenUser {
				require.NotNil(t, returnList)
				require.Equal(t, "config", c.GoString(returnList.Name))
				require.Equal(t, "push \"auth-token-user aWQx\"", c.GoString(returnList.Value))
			} else {
				require.Nil(t, returnList)
			}

			// PluginFuncV3 - OpenVPNPluginClientDisconnect
			args.Type = c.OpenVPNPluginClientDisconnect

			status = PluginFuncV3(PluginStructVerMin, args, ret)
			require.Equal(t, c.OpenVPNPluginFuncSuccess, status)

			// PluginClientDestructorV1
			PluginClientDestructorV1(args.Handle, clientContextPtr)
		})
	}
}

func TestParsePendingPollerTimeout(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		timeout  string
		expected time.Duration
	}{
		{name: "valid", timeout: "600", expected: 10 * time.Minute},
		{name: "zero", timeout: "0", expected: defaultPendingPollerTimeout},
		{name: "negative", timeout: "-1", expected: defaultPendingPollerTimeout},
		{name: "fraction", timeout: "1.5", expected: defaultPendingPollerTimeout},
		{name: "invalid", timeout: "invalid", expected: defaultPendingPollerTimeout},
		{name: "overflow", timeout: strconv.FormatUint(maxPendingPollerTimeoutSeconds+1, 10), expected: defaultPendingPollerTimeout},
		{name: "max", timeout: strconv.FormatUint(maxPendingPollerTimeoutSeconds, 10), expected: time.Duration(maxPendingPollerTimeoutSeconds) * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.expected, parsePendingPollerTimeout(tc.timeout))
		})
	}
}

// TestPluginDenyNonWebAuthClient verifies that a client not supporting webauth
// receives OPENVPN_PLUGIN_FUNC_ERROR so that OpenVPN rejects the connection.
// Previously the plugin returned OPENVPN_PLUGIN_FUNC_SUCCESS on denial, which
// caused OpenVPN to let the client in despite the management-interface deny.
func TestPluginDenyNonWebAuthClient(t *testing.T) {
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

	t.Cleanup(func() {
		testutil.FreeCStringArray(argv, cStrings)
	})

	openArgs := &c.OpenVPNPluginArgsOpenIn{
		Callbacks: testutil.Callbacks(),
		Argv:      argv,
	}
	openRet := &c.OpenVPNPluginArgsOpenReturn{}

	status := PluginOpenV3(PluginStructVerMin, openArgs, openRet)
	require.Equal(t, c.OpenVPNPluginFuncSuccess, status)

	t.Cleanup(func() {
		PluginCloseV1(openRet.Handle)
	})

	args := &c.OpenVPNPluginArgsFuncIn{
		Handle: openRet.Handle,
		Argv:   argv,
		Type:   c.OpenVPNPluginUp,
	}
	ret := &c.OpenVPNPluginArgsFuncReturn{}

	status = PluginFuncV3(PluginStructVerMin, args, ret)
	require.Equal(t, c.OpenVPNPluginFuncSuccess, status)

	// clientListener must not be closed, because it is used by the httpClientListener.
	clientListener, err := nettest.NewLocalListener("tcp")
	require.NoError(t, err)

	conf := config.Defaults
	conf.OpenVPN.Addr = types.URL{URL: &url.URL{Scheme: "unix", Path: unixSocket}}
	conf.OpenVPN.Password = "password"
	conf.OAuth2.OpenVPNUsername = "oauth2TokenClaims." + testsuite.SubjectClaim

	suite := testsuite.New(conf)
	suite.SetupOIDCServer(t, clientListener, nil)

	_, openVPNClient := suite.SetupOpenVPNOAuth2Clients(t.Context(), t, nil)

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

	clientContextPtr := PluginClientConstructorV1(openRet.Handle)
	require.NotNil(t, clientContextPtr)

	authControlFile, err := os.CreateTemp(t.TempDir(), "auth_control_file")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, authControlFile.Close())
	})

	authFailedReasonFile, err := os.CreateTemp(t.TempDir(), "auth_failed_reason_file")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, authFailedReasonFile.Close())
	})

	// Client without webauth support (no IV_SSO=webauth)
	envp, envCStrings := testutil.CreateCStringArray([]string{
		"n_clients=0",
		"password=",
		"session_id=SESSIONID",
		"untrusted_port=17016",
		"untrusted_ip=192.168.65.1",
		"common_name=user@example.com",
		"username=",
		"session_state=Initial",
		"auth_control_file=" + authControlFile.Name(),
		"auth_failed_reason_file=" + authFailedReasonFile.Name(),
	})

	t.Cleanup(func() {
		testutil.FreeCStringArray(envp, envCStrings)
	})

	args = &c.OpenVPNPluginArgsFuncIn{
		Handle:           openRet.Handle,
		Argv:             argv,
		Envp:             envp,
		Type:             c.OpenVPNPluginAuthUserPassVerify,
		PerClientContext: clientContextPtr,
	}
	ret = &c.OpenVPNPluginArgsFuncReturn{}

	// A client without webauth support must be denied: the plugin must return ERROR.
	status = PluginFuncV3(PluginStructVerMin, args, ret)
	require.Equal(t, c.OpenVPNPluginFuncError, status, suite.Logs())

	data, err := os.ReadFile(authFailedReasonFile.Name())
	require.NoError(t, err)
	require.Equal(t, "OpenVPN Client does not support SSO authentication via webauth", string(data))

	PluginClientDestructorV1(args.Handle, clientContextPtr)
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

func TestPluginHandleFromPtr_ZeroHandle(t *testing.T) {
	t.Parallel()

	var (
		handle *PluginHandle
		err    error
	)

	require.NotPanics(t, func() {
		handle, err = pluginHandleFromPtr(c.OpenVPNPluginHandle(0))
	})

	require.Nil(t, handle)
	require.ErrorIs(t, err, errMissingPluginHandle)
}

func TestPluginHandleFromPtr_DeletedHandle(t *testing.T) {
	t.Parallel()

	pluginHandle := c.NewOpenVPNPluginHandle(&PluginHandle{})
	pluginHandle.Delete()

	var (
		handle *PluginHandle
		err    error
	)

	require.NotPanics(t, func() {
		handle, err = pluginHandleFromPtr(pluginHandle)
	})

	require.Nil(t, handle)
	require.ErrorIs(t, err, errInvalidPluginHandle)
}
