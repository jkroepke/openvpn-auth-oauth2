package openvpn_test

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/tokenstorage"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/nettest"
)

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
		name   string
		scheme string
		conf   config.Config
	}{
		{
			name:   "tcp default",
			scheme: openvpn.SchemeTCP,
			conf: func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.Log.Level = slog.LevelDebug
				conf.OpenVpn.Passthrough.Enabled = true

				return conf
			}(),
		},
		{
			name:   "unix default",
			scheme: openvpn.SchemeUnix,
			conf: func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.Log.Level = slog.LevelDebug
				conf.OpenVpn.Passthrough.Enabled = true
				conf.OpenVpn.Passthrough.SocketMode = 0o0600
				conf.OpenVpn.Passthrough.SocketGroup = strconv.Itoa(os.Getgid())

				return conf
			}(),
		},
		{
			name:   "tcp with password",
			scheme: openvpn.SchemeTCP,
			conf: func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.Log.Level = slog.LevelDebug
				conf.OpenVpn.Passthrough.Enabled = true
				conf.OpenVpn.Passthrough.Password = testutils.Secret

				return conf
			}(),
		},
		{
			name:   "tcp with invalid password",
			scheme: openvpn.SchemeTCP,
			conf: func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.Log.Level = slog.LevelDebug
				conf.OpenVpn.Passthrough.Enabled = true
				conf.OpenVpn.Passthrough.Password = testutils.Secret

				return conf
			}(),
		},
	}

	for _, tt := range configs {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)

			logger := testutils.NewTestLogger()

			if tt.scheme == openvpn.SchemeUnix && runtime.GOOS == "windows" {
				t.Skip("skipping test on windows")
			}

			managementInterface, err := nettest.NewLocalListener(openvpn.SchemeTCP)
			require.NoError(t, err)

			t.Cleanup(func() {
				require.NoError(t, managementInterface.Close())
			})

			tt.conf.OpenVpn.Addr = &config.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}

			switch tt.scheme {
			case openvpn.SchemeTCP:
				tt.conf.OpenVpn.Passthrough.Address = &config.URL{Scheme: tt.scheme, Host: "127.0.0.1:0"}
			case openvpn.SchemeUnix:
				temp, err := nettest.LocalPath()
				require.NoError(t, err)

				tt.conf.OpenVpn.Passthrough.Address = &config.URL{Scheme: tt.scheme, Path: temp}
			}

			tokenStorage := tokenstorage.NewInMemory(ctx, testutils.Secret, time.Hour)
			_, openVPNClient := testutils.SetupOpenVPNOAuth2Clients(ctx, t, tt.conf, logger.Logger, http.DefaultClient, tokenStorage)

			managementInterfaceConn, errOpenVPNClientCh, err := testutils.ConnectToManagementInterface(t, managementInterface, openVPNClient)
			require.NoError(t, err)

			reader := bufio.NewReader(managementInterfaceConn)

			if tt.conf.OpenVpn.Password != "" {
				testutils.SendMessage(t, managementInterfaceConn, "ENTER PASSWORD:")
				testutils.ExpectMessage(t, managementInterfaceConn, reader, tt.conf.OpenVpn.Password.String())

				testutils.SendMessage(t, managementInterfaceConn, "SUCCESS: password is correct")
			}

			testutils.ExpectVersionAndReleaseHold(t, managementInterfaceConn, reader)
			testutils.SendMessage(t, managementInterfaceConn, "")
			testutils.SendMessage(t, managementInterfaceConn, "\r\n")

			var passThroughConn net.Conn
			switch tt.scheme {
			case openvpn.SchemeTCP:
				reMatch, err := regexp.Compile(`start pass-through listener on tcp://(\S+:\d+)`)
				require.NoError(t, err)
				passThroughAddr := reMatch.FindStringSubmatch(logger.String())
				require.Len(t, passThroughAddr, 2)

				passThroughConn, err = testutils.WaitUntilListening(t, tt.scheme, passThroughAddr[1])
			case openvpn.SchemeUnix:
				passThroughConn, err = testutils.WaitUntilListening(t, tt.scheme, tt.conf.OpenVpn.Passthrough.Address.Path)
			}

			require.NoError(t, err)

			passThroughReader := bufio.NewReader(passThroughConn)

			if tt.conf.OpenVpn.Passthrough.Password != "" {
				buf := make([]byte, 15)

				_, err = passThroughConn.Read(buf)
				require.NoError(t, err)

				require.Equal(t, "ENTER PASSWORD:", string(buf))

				if strings.Contains(tt.name, "invalid") {
					testutils.SendAndExpectMessage(t, passThroughConn, passThroughReader,
						"invalid",
						"ERROR: bad password",
					)

					openVPNClient.Shutdown()

					select {
					case err := <-errOpenVPNClientCh:
						require.NoError(t, err)
					case <-time.After(1 * time.Second):
						t.Fatalf("timeout waiting for connection to close. Logs:\n\n%s", logger.String())
					}

					return
				}

				testutils.SendAndExpectMessage(t, passThroughConn, passThroughReader,
					tt.conf.OpenVpn.Passthrough.Password.String(),
					"SUCCESS: password is correct",
				)
			}

			testutils.ExpectMessage(t, passThroughConn, passThroughReader, ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info")

			for range 10 {
				testutils.SendMessage(t, passThroughConn, "")
				testutils.SendMessage(t, passThroughConn, "\n")
				testutils.SendMessage(t, passThroughConn, "\r\n")

				testutils.SendAndExpectMessage(t, passThroughConn, passThroughReader,
					"hold",
					"SUCCESS: hold release succeeded",
				)

				// PID
				testutils.SendMessage(t, passThroughConn, "pid")
				testutils.ExpectMessage(t, managementInterfaceConn, reader, "pid")
				testutils.SendMessage(t, managementInterfaceConn, "SUCCESS: pid=7")
				testutils.ExpectMessage(t, passThroughConn, passThroughReader, "SUCCESS: pid=7")

				// unknown command
				testutils.SendMessage(t, passThroughConn, "foo")
				testutils.ExpectMessage(t, managementInterfaceConn, reader, "foo")
				testutils.SendMessage(t, managementInterfaceConn, "ERROR: unknown command, enter 'help' for more options")
				testutils.ExpectMessage(t, passThroughConn, passThroughReader, "ERROR: unknown command, enter 'help' for more options")

				// kill 1
				testutils.SendMessage(t, passThroughConn, "kill 1")
				testutils.ExpectMessage(t, managementInterfaceConn, reader, "kill 1")
				testutils.SendMessage(t, managementInterfaceConn, "ERROR: common name '1' not found")
				testutils.ExpectMessage(t, passThroughConn, passThroughReader, "ERROR: common name '1' not found")

				// client-auth-nt 1
				testutils.SendAndExpectMessage(t, passThroughConn, passThroughReader,
					"client-auth-nt 1",
					"ERROR: command not allowed",
				)

				// client-kill 1
				testutils.SendMessage(t, passThroughConn, "client-kill 1")
				testutils.ExpectMessage(t, managementInterfaceConn, reader, "client-kill 1")
				testutils.SendMessage(t, managementInterfaceConn, "ERROR: client-kill command failed")
				testutils.ExpectMessage(t, passThroughConn, passThroughReader, "ERROR: client-kill command failed")

				// version
				testutils.SendMessage(t, passThroughConn, "version")
				testutils.ExpectMessage(t, managementInterfaceConn, reader, "version")
				testutils.SendMessage(t, managementInterfaceConn, "OpenVPN Version: openvpn-auth-oauth2\r\nManagement Interface Version: 5\r\nEND")
				testutils.ExpectMessage(t, passThroughConn, passThroughReader, "OpenVPN Version: openvpn-auth-oauth2\r\nManagement Interface Version: 5\r\nEND")

				// status
				testutils.SendMessage(t, passThroughConn, "status")
				testutils.ExpectMessage(t, managementInterfaceConn, reader, "status")
				testutils.SendMessage(t, managementInterfaceConn, OpenVPNManagementInterfaceCommandResultStatus)
				testutils.ExpectMessage(t, passThroughConn, passThroughReader, OpenVPNManagementInterfaceCommandResultStatus)

				// status 2
				testutils.SendMessage(t, passThroughConn, "status 2")
				testutils.ExpectMessage(t, managementInterfaceConn, reader, "status 2")
				testutils.SendMessage(t, managementInterfaceConn, OpenVPNManagementInterfaceCommandResultStatus2)
				testutils.ExpectMessage(t, passThroughConn, passThroughReader, OpenVPNManagementInterfaceCommandResultStatus2)

				// status 3
				testutils.SendMessage(t, passThroughConn, "status 3")
				testutils.ExpectMessage(t, managementInterfaceConn, reader, "status 3")
				testutils.SendMessage(t, managementInterfaceConn, OpenVPNManagementInterfaceCommandResultStatus3)
				testutils.ExpectMessage(t, passThroughConn, passThroughReader, OpenVPNManagementInterfaceCommandResultStatus3)
			}

			// help
			for range 10 {
				testutils.SendMessage(t, passThroughConn, "help")
				testutils.ExpectMessage(t, managementInterfaceConn, reader, "help")
				testutils.SendMessage(t, managementInterfaceConn, OpenVPNManagementInterfaceCommandResultHelp)
				testutils.ExpectMessage(t, passThroughConn, passThroughReader, OpenVPNManagementInterfaceCommandResultHelp)
			}

			if tt.scheme == openvpn.SchemeUnix {
				testutils.SendMessage(t, passThroughConn, " exit ")
				require.NoError(t, passThroughConn.Close())

				gid, err := testutils.GetGIDOfFile(tt.conf.OpenVpn.Passthrough.Address.Path)
				require.NoError(t, err)

				assert.Equal(t, tt.conf.OpenVpn.Passthrough.SocketGroup, strconv.Itoa(gid))

				permission, err := testutils.GetPermissionsOfFile(tt.conf.OpenVpn.Passthrough.Address.Path)
				require.NoError(t, err)

				assert.Equal(t, os.FileMode(tt.conf.OpenVpn.Passthrough.SocketMode).String(), permission) //nolint:gosec
			} else {
				testutils.SendMessage(t, passThroughConn, " quit ")
				require.NoError(t, passThroughConn.Close())
			}

			openVPNClient.Shutdown()

			select {
			case err := <-errOpenVPNClientCh:
				require.NoError(t, err)
			case <-time.After(1 * time.Second):
				t.Fatalf("timeout waiting for connection to close. Logs:\n\n%s", logger.String())
			}
		})
	}
}
