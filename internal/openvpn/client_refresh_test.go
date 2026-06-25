package openvpn_test

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	configtypes "github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	oauth2types "github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn/connection"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/test/testsuite"
	"github.com/stretchr/testify/require"
)

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
