package openvpn_test

import (
	"context"
	"log/slog"
	"net"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/test/testsuite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/nettest"
)

var rePassThroughLogListen = regexp.MustCompile(`"start pass-through listener on (?:tcp|unix)://(\S+)"`)

const OpenVPNManagementInterfaceCommandResultStatus = `OpenVPN CLIENT LIST
Updated,2024-02-17 10:55:19
Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
ROUTING TABLE
Virtual Address,Common Name,Real Address,Last Ref
GLOBAL STATS
Max bcast/mcast queue length,0
END`

const OpenVPNManagementInterfaceCommandResultHelp = `Management Interface for OpenVPN 2.6.9 [git:release/2.6/6640a10bf6d84eee] x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] [DCO] built on Feb 17 2024
Commands:
auth-retry t           : Auth failure retry mode (none,interact,nointeract).
bytecount n            : Show bytes in/out, update every n secs (0=off).
echo [on|off] [N|all]  : Like log, but only show messages in echo buffer.
cr-response response   : Send a challenge response answer via CR_RESPONSE to server
exit|quit              : Close management session.
forget-passwords       : Forget passwords entered so far.
help                   : Print this message.
hold [on|off|release]  : Set/show hold flag to on/off state, or
                         release current hold and start tunnel.
kill cn                : Kill the client instance(s) having common name cn.
kill IP:port           : Kill the client instance connecting from IP:port.
load-stats             : Show global server load stats.
log [on|off] [N|all]   : Turn on/off realtime log display
                         + show last N lines or 'all' for entire history.
mute [n]               : Set log mute level to n, or show level if n is absent.
needok type action     : Enter confirmation for NEED-OK request of 'type',
                         where action = 'ok' or 'cancel'.
needstr type action    : Enter confirmation for NEED-STR request of 'type',
                         where action is reply string.
net                    : (Windows only) Show network info and routing table.
password type p        : Enter password p for a queried OpenVPN password.
remote type [host port] : Override remote directive, type=ACCEPT|MOD|SKIP.
remote-entry-count     : Get number of available remote entries.
remote-entry-get  i|all [j]: Get remote entry at index = i to to j-1 or all.
proxy type [host port flags] : Enter dynamic proxy server info.
pid                    : Show process ID of the current OpenVPN process.
client-auth CID KID    : Authenticate client-id/key-id CID/KID (MULTILINE)
client-auth-nt CID KID : Authenticate client-id/key-id CID/KID
client-deny CID KID R [CR] : Deny auth client-id/key-id CID/KID with log reason
                             text R and optional client reason text CR
client-pending-auth CID KID MSG timeout : Instruct OpenVPN to send AUTH_PENDING and INFO_PRE msg
                                      to the client and wait for a final client-auth/client-deny
client-kill CID [M]    : Kill client instance CID with message M (def=RESTART)
env-filter [level]     : Set env-var filter level
rsa-sig                : Enter a signature in response to >RSA_SIGN challenge
                         Enter signature base64 on subsequent lines followed by END
pk-sig                 : Enter a signature in response to >PK_SIGN challenge
                         Enter signature base64 on subsequent lines followed by END
certificate            : Enter a client certificate in response to >NEED-CERT challenge
                         Enter certificate base64 on subsequent lines followed by END
signal s               : Send signal s to daemon,
                         s = SIGHUP|SIGTERM|SIGUSR1|SIGUSR2.
state [on|off] [N|all] : Like log, but show state history.
status [n]             : Show current daemon status info using format #n.
test n                 : Produce n lines of output for testing/debugging.
username type u        : Enter username u for a queried OpenVPN username.
verb [n]               : Set log verbosity level to n, or show if n is absent.
version [n]            : Set client's version to n or show current version of daemon.
END
`

const OpenVPNManagementInterfaceCommandResultStatus2 = `TITLE,OpenVPN 2.6.9 [git:release/2.6/6640a10bf6d84eee] x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] [DCO] built on Mar 16 2024
TIME,2024-03-23 16:00:26,1711209626
HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID,Data Channel Cipher
HEADER,ROUTING_TABLE,Virtual Address,Common Name,Real Address,Last Ref,Last Ref (time_t)
GLOBAL_STATS,Max bcast/mcast queue length,0
GLOBAL_STATS,dco_enabled,0
END
`

const OpenVPNManagementInterfaceCommandResultStatus3 = `TITLE	OpenVPN 2.6.9 [git:release/2.6/6640a10bf6d84eee] x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD] [DCO] built on Mar 16 2024
TIME	2024-03-23 16:00:26	1711209626
HEADER	CLIENT_LIST	Common Name	Real Address	Virtual Address	Virtual IPv6 Address	Bytes Received	Bytes Sent	Connected Since	Connected Since (time_t)	Username	Client ID	Peer ID	Data Channel Cipher
HEADER	ROUTING_TABLE	Virtual Address	Common Name	Real Address	Last Ref	Last Ref (time_t)
GLOBAL_STATS	Max bcast/mcast queue length	0
GLOBAL_STATS	dco_enabled	0
END
`

func TestPassThroughFull(t *testing.T) {
	t.Parallel()

	configs := []struct {
		name            string
		scheme          string
		conf            config.Config
		invalidPassword bool
	}{
		{
			name:   "tcp without password",
			scheme: openvpn.SchemeTCP,
			conf:   newPassThroughTestConfig(""),
		},
		{
			name:   "unix with password",
			scheme: openvpn.SchemeUnix,
			conf: func() config.Config {
				conf := newPassThroughTestConfig(testsuite.Secret)
				conf.OpenVPN.Passthrough.SocketMode = 0o0600
				conf.OpenVPN.Passthrough.SocketGroup = strconv.Itoa(os.Getgid())

				return conf
			}(),
		},
		{
			name:   "tcp with password",
			scheme: openvpn.SchemeTCP,
			conf:   newPassThroughTestConfig(testsuite.Secret),
		},
		{
			name:            "tcp with invalid password",
			scheme:          openvpn.SchemeTCP,
			conf:            newPassThroughTestConfig(testsuite.Secret),
			invalidPassword: true,
		},
	}

	for _, tc := range configs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)

			suite, passThroughConn, passThroughNetConn := setupPassThroughConnection(ctx, t, tc.scheme, &tc.conf)
			if !authenticatePassThroughConnection(t, tc.conf, passThroughNetConn, passThroughConn, tc.invalidPassword) {
				return
			}

			passThroughConn.ExpectMessage(t, openvpn.WelcomeBanner)

			for range 10 {
				passThroughConn.SendMessagef(t, "")
				passThroughConn.SendMessagef(t, "\n")
				passThroughConn.SendMessagef(t, "\r\n")

				passThroughConn.SendAndExpectMessage(t, "hold", "SUCCESS: hold release succeeded")

				// PID
				forwardPassThroughCommand(t, suite, passThroughConn, "pid", "SUCCESS: pid=7")

				// unknown command
				forwardPassThroughCommand(t, suite, passThroughConn, "foo", "ERROR: unknown command, enter 'help' for more options")

				// kill 1
				forwardPassThroughCommand(t, suite, passThroughConn, "kill 1", "SUCCESS: common name '1' killed")

				// auth decision commands are owned by openvpn-auth-oauth2.
				passThroughConn.SendAndExpectMessage(t, "client-auth 1 2", "ERROR: command not allowed")
				passThroughConn.SendAndExpectMessage(t, "client-auth-nt 1", "ERROR: command not allowed")
				passThroughConn.SendAndExpectMessage(t, "client-deny 1 2 reason", "ERROR: command not allowed")
				passThroughConn.SendAndExpectMessage(t, "client-pending-auth 1 2 msg 10", "ERROR: command not allowed")

				// client-kill 1
				forwardPassThroughCommand(t, suite, passThroughConn, "client-kill 1", "ERROR: client-kill command failed")

				// version with argument changes client version
				forwardPassThroughCommand(t, suite, passThroughConn, "version 3", "SUCCESS: version=3")

				// Forwarded secret-bearing commands must not log the secret value.
				forwardPassThroughCommand(t, suite, passThroughConn, "password Auth super-secret-value", "SUCCESS: password is correct")
				require.NotContains(t, suite.Logs(), "super-secret-value")

				// version
				forwardPassThroughCommand(t, suite, passThroughConn, "version", "OpenVPN Version: openvpn-auth-oauth2\r\nManagement Interface Version: 5\r\nEND")

				// status
				forwardPassThroughCommand(t, suite, passThroughConn, "status", OpenVPNManagementInterfaceCommandResultStatus)

				// status 2
				forwardPassThroughCommand(t, suite, passThroughConn, "status 2", OpenVPNManagementInterfaceCommandResultStatus2)

				// status 3
				forwardPassThroughCommand(t, suite, passThroughConn, "status 3", OpenVPNManagementInterfaceCommandResultStatus3)
			}

			// help
			for range 10 {
				forwardPassThroughCommand(t, suite, passThroughConn, "help", OpenVPNManagementInterfaceCommandResultHelp)
			}

			if tc.scheme == openvpn.SchemeUnix {
				passThroughConn.SendMessagef(t, " exit ")
				require.NoError(t, passThroughNetConn.Close())

				gid, err := testsuite.GetGIDOfFile(tc.conf.OpenVPN.Passthrough.Address.Path)
				require.NoError(t, err)

				assert.Equal(t, tc.conf.OpenVPN.Passthrough.SocketGroup, strconv.Itoa(gid))

				permission, err := testsuite.GetPermissionsOfFile(tc.conf.OpenVPN.Passthrough.Address.Path)
				require.NoError(t, err)

				//nolint:gosec
				assert.Equal(t, os.FileMode(tc.conf.OpenVPN.Passthrough.SocketMode).String(), permission)
			} else {
				passThroughConn.SendMessagef(t, " quit ")
				require.NoError(t, passThroughNetConn.Close())
			}
		})
	}
}

func TestPassThroughCommandTimeoutSanitizesLogs(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	conf := newPassThroughTestConfig(testsuite.Secret)
	conf.OpenVPN.CommandTimeout = 100 * time.Millisecond

	suite, passThroughConn, passThroughNetConn := setupPassThroughConnection(ctx, t, openvpn.SchemeTCP, &conf)
	require.True(t, authenticatePassThroughConnection(t, conf, passThroughNetConn, passThroughConn, false))
	passThroughConn.ExpectMessage(t, openvpn.WelcomeBanner)

	passThroughConn.SendMessagef(t, "password Auth super-secret-value")
	suite.ExpectMessage(t, "password Auth super-secret-value")

	require.Eventually(t, func() bool {
		logs := suite.Logs()

		return strings.Contains(logs, "pass-through: command failed") &&
			strings.Contains(logs, "command error 'password'")
	}, time.Second, 10*time.Millisecond, suite.Logs())

	require.NotContains(t, suite.Logs(), "super-secret-value")
}

func newPassThroughTestConfig(password string) config.Config {
	conf := config.Defaults
	conf.HTTP.Secret = testsuite.Secret
	conf.Log.Level = slog.LevelDebug
	conf.OpenVPN.Passthrough.Enabled = true
	conf.OpenVPN.Passthrough.Password = types.Secret(password)

	return conf
}

func setupPassThroughConnection(
	ctx context.Context,
	t *testing.T,
	scheme string,
	conf *config.Config,
) (*testsuite.Suite, *testsuite.Conn, net.Conn) {
	t.Helper()

	if scheme == openvpn.SchemeUnix && runtime.GOOS == "windows" {
		t.Skip("skipping test on windows")
	}

	switch scheme {
	case openvpn.SchemeTCP:
		conf.OpenVPN.Passthrough.Address = types.URL{URL: &url.URL{Scheme: scheme, Host: "127.0.0.1:0"}}
	case openvpn.SchemeUnix:
		temp, err := nettest.LocalPath()
		require.NoError(t, err)

		conf.OpenVPN.Passthrough.Address = types.URL{URL: &url.URL{Scheme: scheme, Path: temp}}
	}

	suite := testsuite.New(conf)
	errOpenVPNClientCh := suite.SetupManagementEnvironment(ctx, t, nil)
	openVPNClient := suite.GetOpenVPNClient()

	var passThroughNetConn net.Conn

	t.Cleanup(func() {
		if passThroughNetConn != nil {
			_ = passThroughNetConn.Close()
		}

		openVPNClient.Shutdown(t.Context())

		select {
		case err := <-errOpenVPNClientCh:
			require.NoError(t, err, suite.Logs())
		case <-time.After(1 * time.Second):
			t.Fatalf("timeout waiting for connection to close. Logs:\n\n%s", suite.Logs())
		}
	})

	if conf.OpenVPN.Password != "" {
		suite.SendMessagef(t, "ENTER PASSWORD:")
		suite.ExpectMessage(t, conf.OpenVPN.Password.String())
		suite.SendMessagef(t, "SUCCESS: password is correct")
	}

	suite.ExpectVersionAndReleaseHold(t)
	suite.SendMessagef(t, "")
	suite.SendMessagef(t, "\r\n")

	passThroughNetConn = dialPassThroughConnection(ctx, t, suite, scheme)

	return suite, testsuite.NewConn(passThroughNetConn).WithLogs(suite.Logs), passThroughNetConn
}

func dialPassThroughConnection(ctx context.Context, t *testing.T, suite *testsuite.Suite, scheme string) net.Conn {
	t.Helper()

	var passThroughAddr []string

	require.Eventually(t, func() bool {
		passThroughAddr = rePassThroughLogListen.FindStringSubmatch(suite.Logs())

		return passThroughAddr != nil
	}, time.Second, 50*time.Millisecond)

	require.Len(t, passThroughAddr, 2, "unexpected log output: %s", suite.Logs())

	passThroughNetConn, err := testsuite.WaitUntilListening(ctx, t, scheme, passThroughAddr[1])
	require.NoError(t, err)

	return passThroughNetConn
}

func authenticatePassThroughConnection(
	t *testing.T,
	conf config.Config,
	passThroughNetConn net.Conn,
	passThroughConn *testsuite.Conn,
	invalidPassword bool,
) bool {
	t.Helper()

	if conf.OpenVPN.Passthrough.Password.String() == "" {
		return true
	}

	buf := make([]byte, 15)
	_, err := passThroughNetConn.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "ENTER PASSWORD:", string(buf))

	if invalidPassword {
		passThroughConn.SendAndExpectMessage(t, "invalid", "ERROR: bad password")

		return false
	}

	passThroughConn.SendAndExpectMessage(t, conf.OpenVPN.Passthrough.Password.String(), "SUCCESS: password is correct")

	return true
}

func forwardPassThroughCommand(t *testing.T, suite *testsuite.Suite, passThroughConn *testsuite.Conn, command, response string) {
	t.Helper()

	passThroughConn.SendMessagef(t, command)
	suite.ExpectMessage(t, command)
	suite.SendMessagef(t, response)
	passThroughConn.ExpectMessage(t, response)
}
