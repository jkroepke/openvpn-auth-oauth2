package openvpn_test

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	configtypes "github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
	oauth2types "github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/openvpn/connection"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/test/testsuite"
	"github.com/stretchr/testify/require"
)

func TestClientAuthenticationEventsProcessConcurrently(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	conf := config.Defaults
	conf.OAuth2.Refresh.Enabled = true
	conf.OAuth2.Refresh.ValidateUser = true

	suite := testsuite.New(&conf)
	suite.SetupManagementEnvironment(ctx, t, nil)

	oauth2Client := newBlockingRefreshOAuth2Client()
	suite.GetOpenVPNClient().SetOAuth2Client(oauth2Client)
	t.Cleanup(func() {
		suite.Close(t)
	})
	t.Cleanup(oauth2Client.release)

	suite.ExpectVersionAndReleaseHold(t)
	suite.SendMessagef(
		t,
		">CLIENT:CONNECT,1,1\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n"+
			">CLIENT:ENV,common_name=first\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END",
	)

	select {
	case <-oauth2Client.blockedFirst:
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for first refresh to block. Logs:\n\n%s", suite.Logs())
	}

	suite.SendMessagef(
		t,
		">CLIENT:CONNECT,2,1\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n"+
			">CLIENT:ENV,common_name=second\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END",
	)

	auth, err := readOpenVPNManagementLine(t, suite, time.Second)
	require.NoError(t, err, suite.Logs())
	require.Contains(t, auth, `client-pending-auth 2 1 "WEB_AUTH::`, suite.Logs())
	suite.SendMessagef(t, "SUCCESS: client-pending-auth command succeeded")

	oauth2Client.release()

	auth, err = readOpenVPNManagementLine(t, suite, time.Second)
	require.NoError(t, err, suite.Logs())
	require.Contains(t, auth, `client-pending-auth 1 1 "WEB_AUTH::`, suite.Logs())
	suite.SendMessagef(t, "SUCCESS: client-pending-auth command succeeded")
}

func TestClientAuthenticationEventsKeepSameClientOrder(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	conf := config.Defaults
	conf.OAuth2.Refresh.Enabled = true
	conf.OAuth2.Refresh.ValidateUser = true

	suite := testsuite.New(&conf)
	suite.SetupManagementEnvironment(ctx, t, nil)

	oauth2Client := newBlockingRefreshOAuth2Client()
	suite.GetOpenVPNClient().SetOAuth2Client(oauth2Client)
	t.Cleanup(func() {
		suite.Close(t)
	})
	t.Cleanup(oauth2Client.release)

	suite.ExpectVersionAndReleaseHold(t)
	suite.SendMessagef(
		t,
		">CLIENT:CONNECT,1,1\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n"+
			">CLIENT:ENV,common_name=first\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END",
	)

	select {
	case <-oauth2Client.blockedFirst:
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for first refresh to block. Logs:\n\n%s", suite.Logs())
	}

	suite.SendMessagef(
		t,
		">CLIENT:CONNECT,1,2\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n"+
			">CLIENT:ENV,common_name=second\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END",
	)

	_, err := readOpenVPNManagementLine(t, suite, 100*time.Millisecond)
	require.ErrorIs(t, err, os.ErrDeadlineExceeded, suite.Logs())

	oauth2Client.release()

	auth, err := readOpenVPNManagementLine(t, suite, time.Second)
	require.NoError(t, err, suite.Logs())
	require.Contains(t, auth, `client-pending-auth 1 1 "WEB_AUTH::`, suite.Logs())
	suite.SendMessagef(t, "SUCCESS: client-pending-auth command succeeded")

	auth, err = readOpenVPNManagementLine(t, suite, time.Second)
	require.NoError(t, err, suite.Logs())
	require.Contains(t, auth, `client-pending-auth 1 2 "WEB_AUTH::`, suite.Logs())
	suite.SendMessagef(t, "SUCCESS: client-pending-auth command succeeded")
}

func TestSilentAuthenticationEnforcesUniqueUser(t *testing.T) {
	t.Parallel()

	for _, reason := range []string{"CONNECT", "REAUTH"} {
		t.Run(reason, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)

			conf := config.Defaults
			conf.OAuth2.Refresh.Enabled = true
			conf.OAuth2.Refresh.ValidateUser = true
			conf.OpenVPN.EnforceUniqueUser = true
			conf.OpenVPN.OverrideUsername = true

			suite := testsuite.New(&conf)
			errOpenVPNClientCh := suite.SetupManagementEnvironment(ctx, t, nil)
			suite.GetOpenVPNClient().SetOAuth2Client(&storedProfileOAuth2Client{})
			suite.ExpectVersionAndReleaseHold(t)

			suite.SendMessagef(
				t,
				">CLIENT:%s,10,3\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n"+
					">CLIENT:ENV,session_id=session_id\r\n>CLIENT:ENV,session_state=Authenticated\r\n"+
					">CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END",
				reason,
			)

			suite.ExpectMessage(t, "status 3")
			suite.SendMessagef(
				t,
				"HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\t"+
					"Bytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher\r\n"+
					"CLIENT_LIST\tclient\t127.0.0.1:1194\t10.8.0.2\t\t1\t2\tnow\t1\talice\t7\t0\tAES-256-GCM\r\n"+
					"CLIENT_LIST\tclient\t127.0.0.1:1194\t10.8.0.3\t\t1\t2\tnow\t1\talice\t10\t0\tAES-256-GCM\r\nEND",
			)
			suite.ExpectMessage(t, "client-kill 7")
			suite.SendMessagef(t, "SUCCESS: client-kill command succeeded")
			suite.ExpectMessage(t, "client-auth 10 3\r\noverride-username \"alice\"\r\nEND")
			suite.SendMessagef(t, "SUCCESS: client-auth command succeeded")

			require.NoError(t, suite.GetManagementInterfaceConn().Close())

			select {
			case err := <-errOpenVPNClientCh:
				require.NoError(t, err, suite.Logs())
			case <-time.After(time.Second):
				t.Fatalf("timeout waiting for connection to close. Logs:\n\n%s", suite.Logs())
			}
		})
	}
}

func TestSilentReAuthenticationUsesStoredSelectedProfile(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	conf := config.Defaults
	conf.OAuth2.Refresh.Enabled = true
	conf.OAuth2.Refresh.ValidateUser = true
	conf.OpenVPN.AuthTokenUser = false
	conf.OpenVPN.ClientConfig.Enabled = true
	conf.OpenVPN.ClientConfig.Strategy = config.OpenVPNConfigStrategyUserSelector
	conf.OpenVPN.ClientConfig.Path = configtypes.FS{
		FS: fstest.MapFS{
			"first.conf": {
				Data: []byte("push \"route 10.1.0.0 255.255.0.0\"\n"),
			},
			"selected.conf": {
				Data: []byte("push \"route 10.2.0.0 255.255.0.0\"\n"),
			},
		},
	}

	suite := testsuite.New(&conf)
	errOpenVPNClientCh := suite.SetupManagementEnvironment(ctx, t, nil)
	oauth2Client := &storedProfileOAuth2Client{}
	suite.GetOpenVPNClient().SetOAuth2Client(oauth2Client)
	suite.ExpectVersionAndReleaseHold(t)

	suite.SendMessagef(
		t,
		">CLIENT:REAUTH,1,3\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n"+
			">CLIENT:ENV,session_id=session_id\r\n>CLIENT:ENV,session_state=AuthenticatedEmptyUser\r\n"+
			">CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END",
	)

	suite.ExpectMessage(t, "client-auth 1 3\r\n"+
		"push \"route 10.2.0.0 255.255.0.0\"\r\n"+
		"END")
	suite.SendMessagef(t, "SUCCESS: client-auth command succeeded")
	require.Zero(t, oauth2Client.resolveCalls.Load())

	require.NoError(t, suite.GetManagementInterfaceConn().Close())

	select {
	case err := <-errOpenVPNClientCh:
		require.NoError(t, err, suite.Logs())
	case <-time.After(time.Second):
		t.Fatalf("timeout waiting for connection to close. Logs:\n\n%s", suite.Logs())
	}
}

func readOpenVPNManagementLine(t *testing.T, suite *testsuite.Suite, timeout time.Duration) (string, error) {
	t.Helper()

	require.NoError(t, suite.GetManagementInterfaceConn().SetReadDeadline(time.Now().Add(timeout)))

	line, err := suite.GetManagementInterfaceConnReader().ReadString('\n')

	return strings.TrimSpace(line), err
}

type blockingRefreshOAuth2Client struct {
	blockedFirst chan struct{}
	releaseFirst chan struct{}
	releaseOnce  sync.Once
	firstBlocked atomic.Bool
}

func newBlockingRefreshOAuth2Client() *blockingRefreshOAuth2Client {
	return &blockingRefreshOAuth2Client{
		blockedFirst: make(chan struct{}),
		releaseFirst: make(chan struct{}),
	}
}

func (c *blockingRefreshOAuth2Client) RefreshClientAuth(
	ctx context.Context,
	_ *slog.Logger,
	client connection.Client,
) (oauth2types.UserInfo, *idtoken.IDToken, []string, bool, error) {
	if client.CID == 1 && c.firstBlocked.CompareAndSwap(false, true) {
		close(c.blockedFirst)

		select {
		case <-ctx.Done():
			return oauth2types.UserInfo{}, nil, nil, false, ctx.Err()
		case <-c.releaseFirst:
		}
	}

	return oauth2types.UserInfo{}, nil, nil, false, nil
}

func (c *blockingRefreshOAuth2Client) ResolveClientConfigNames(
	_ *idtoken.IDToken,
	_, _ string,
) ([]string, error) {
	return nil, nil
}

func (c *blockingRefreshOAuth2Client) ClientDisconnect(context.Context, *slog.Logger, connection.Client) {
}

func (c *blockingRefreshOAuth2Client) EncryptState(state.State) (state.EncryptedState, error) {
	return "state", nil
}

func (c *blockingRefreshOAuth2Client) release() {
	c.releaseOnce.Do(func() {
		close(c.releaseFirst)
	})
}

type storedProfileOAuth2Client struct {
	resolveCalls atomic.Int32
}

func (c *storedProfileOAuth2Client) RefreshClientAuth(
	context.Context,
	*slog.Logger,
	connection.Client,
) (oauth2types.UserInfo, *idtoken.IDToken, []string, bool, error) {
	return oauth2types.UserInfo{Username: "alice"}, &idtoken.IDToken{
		IDTokenClaims: &idtoken.Claims{Claims: map[string]any{}},
	}, []string{"selected"}, true, nil
}

func (c *storedProfileOAuth2Client) ResolveClientConfigNames(
	_ *idtoken.IDToken,
	_, _ string,
) ([]string, error) {
	c.resolveCalls.Add(1)

	return []string{"first", "selected"}, nil
}

func (c *storedProfileOAuth2Client) ClientDisconnect(context.Context, *slog.Logger, connection.Client) {
}

func (c *storedProfileOAuth2Client) EncryptState(state.State) (state.EncryptedState, error) {
	return "", nil
}
