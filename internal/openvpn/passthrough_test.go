package openvpn_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/storage"
	"github.com/jkroepke/openvpn-auth-oauth2/pkg/testutils"
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

func TestPassthroughFull(t *testing.T) {
	t.Parallel()

	logger := testutils.NewTestLogger()

	conf := config.Defaults
	conf.HTTP.Secret = testutils.Secret
	conf.OpenVpn.Passthrough.Enabled = true

	confs := []struct {
		name   string
		scheme string
		conf   config.Config
	}{
		{
			name:   "tcp default",
			scheme: openvpn.SchemeTCP,
			conf: func() config.Config {
				conf := conf

				return conf
			}(),
		},
		{
			name:   "unix default",
			scheme: openvpn.SchemeUnix,
			conf: func() config.Config {
				conf := conf
				conf.OpenVpn.Passthrough.SocketMode = 0o0600
				conf.OpenVpn.Passthrough.SocketGroup = strconv.Itoa(os.Getgid())

				return conf
			}(),
		},
		{
			name:   "tcp with password",
			scheme: openvpn.SchemeTCP,
			conf: func() config.Config {
				conf := conf
				conf.OpenVpn.Passthrough.Password = testutils.Secret

				return conf
			}(),
		},
		{
			name:   "tcp with invalid password",
			scheme: openvpn.SchemeTCP,
			conf: func() config.Config {
				conf := conf
				conf.OpenVpn.Passthrough.Password = testutils.Secret

				return conf
			}(),
		},
	}

	for _, tt := range confs {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			managementInterface, err := nettest.NewLocalListener(openvpn.SchemeTCP)
			require.NoError(t, err)

			defer managementInterface.Close()

			passThroughInterface, err := nettest.NewLocalListener(tt.scheme)
			require.NoError(t, err)

			tt.conf.OpenVpn.Addr = &url.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}
			switch tt.scheme {
			case openvpn.SchemeTCP:
				tt.conf.OpenVpn.Passthrough.Address = &url.URL{Scheme: tt.scheme, Host: passThroughInterface.Addr().String()}
			case openvpn.SchemeUnix:
				tt.conf.OpenVpn.Passthrough.Address = &url.URL{Scheme: tt.scheme, Path: passThroughInterface.Addr().String()}
			}

			passThroughInterface.Close()

			storageClient := storage.New(testutils.Secret, time.Hour)
			provider := oauth2.New(logger.Logger, tt.conf, storageClient)
			openVPNClient := openvpn.NewClient(context.Background(), logger.Logger, tt.conf, provider)

			defer openVPNClient.Shutdown()

			wg := sync.WaitGroup{}

			ctx, cancel := context.WithCancelCause(context.Background())

			wg.Add(1)

			go func() {
				defer wg.Done()

				managementInterfaceConn, err := managementInterface.Accept()
				if err != nil {
					cancel(fmt.Errorf("accepting connection: %w", err))

					return
				}

				defer managementInterfaceConn.Close()

				reader := bufio.NewReader(managementInterfaceConn)

				if tt.conf.OpenVpn.Password != "" {
					testutils.SendMessage(t, managementInterfaceConn, "ENTER PASSWORD:")
					testutils.ExpectMessage(t, managementInterfaceConn, reader, tt.conf.OpenVpn.Password.String())

					testutils.SendMessage(t, managementInterfaceConn, "SUCCESS: password is correct")
				}

				testutils.ExpectVersionAndReleaseHold(t, managementInterfaceConn, reader)

				var message string

				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						cancel(fmt.Errorf("reading line: %w", err))

						return
					}

					line = strings.TrimSpace(line)

					if line == "exit" {
						cancel(nil)

						break
					}

					switch line {
					case "help":
						message = OpenVPNManagementInterfaceCommandResultHelp
					case "status":
						message = OpenVPNManagementInterfaceCommandResultStatus
					case "version":
						message = "OpenVPN Version: openvpn-auth-oauth2\r\nManagement Interface Version: 5\r\nEND"
					case "load-stats":
						message = "SUCCESS: nclients=0,bytesin=0,bytesout=0"
					case "pid":
						message = "SUCCESS: pid=7"
					case "kill 1":
						message = "ERROR: common name '1' not found"
					case "client-kill 1":
						message = "ERROR: client-kill command failed"
					default:
						message = "ERROR: unknown command, enter 'help' for more options"
					}

					testutils.SendMessage(t, managementInterfaceConn, message+"")
				}
			}()

			wg.Add(1)

			go func() {
				defer wg.Done()

				err := openVPNClient.Connect()
				if err != nil {
					cancel(fmt.Errorf("connecting: %w", err))

					return
				}

				<-ctx.Done()
			}()

			wg.Add(1)

			go func() {
				defer wg.Done()

				var passThroughConn net.Conn

				for i := 0; i < 100; i++ {
					passThroughConn, err = net.DialTimeout(passThroughInterface.Addr().Network(), passThroughInterface.Addr().String(), time.Second)
					if err == nil {
						break
					}

					time.Sleep(50 * time.Millisecond)
				}

				if err != nil {
					cancel(fmt.Errorf("dialing: %w", err))

					return
				}

				passThroughReader := bufio.NewReader(passThroughConn)

				if tt.conf.OpenVpn.Passthrough.Password != "" {
					buf := make([]byte, 15)

					_, err = passThroughConn.Read(buf)
					if err != nil {
						cancel(fmt.Errorf("reading password prompt: %w", err))

						return
					}

					assert.Equal(t, "ENTER PASSWORD:", string(buf))

					if strings.Contains(tt.name, "invalid") {
						testutils.SendAndExpectMessage(t, passThroughConn, passThroughReader,
							"invalid",
							"ERROR: bad password",
						)

						cancel(nil)

						return
					}

					testutils.SendAndExpectMessage(t, passThroughConn, passThroughReader,
						tt.conf.OpenVpn.Passthrough.Password.String(),
						"SUCCESS: password is correct",
					)
				}

				for i := 0; i < 10; i++ {
					testutils.SendAndExpectMessage(t, passThroughConn, passThroughReader,
						"hold",
						"SUCCESS: hold release succeeded",
					)

					testutils.SendAndExpectMessage(t, passThroughConn, passThroughReader,
						"pid",
						"SUCCESS: pid=7",
					)

					testutils.SendAndExpectMessage(t, passThroughConn, passThroughReader,
						"foo",
						"ERROR: unknown command, enter 'help' for more options",
					)

					testutils.SendAndExpectMessage(t, passThroughConn, passThroughReader,
						"kill 1",
						"ERROR: common name '1' not found",
					)

					testutils.SendAndExpectMessage(t, passThroughConn, passThroughReader,
						"client-auth-nt 1",
						"ERROR: command not allowed",
					)

					testutils.SendAndExpectMessage(t, passThroughConn, passThroughReader,
						"client-kill 1",
						"ERROR: client-kill command failed",
					)

					testutils.SendAndExpectMessage(t, passThroughConn, passThroughReader,
						"version",
						"OpenVPN Version: openvpn-auth-oauth2\r\nManagement Interface Version: 5\r\nEND",
					)

					testutils.SendAndExpectMessage(t, passThroughConn, passThroughReader,
						"status",
						OpenVPNManagementInterfaceCommandResultStatus,
					)

					testutils.SendAndExpectMessage(t, passThroughConn, passThroughReader,
						"help",
						OpenVPNManagementInterfaceCommandResultHelp,
					)
				}

				for i := 0; i < 10; i++ {
					testutils.SendAndExpectMessage(t, passThroughConn, passThroughReader,
						"help",
						OpenVPNManagementInterfaceCommandResultHelp,
					)
				}

				if tt.scheme == openvpn.SchemeUnix {
					testutils.SendMessage(t, passThroughConn, "exit")

					stat, err := os.Stat(passThroughInterface.Addr().String())
					if err != nil {
						cancel(fmt.Errorf("stat: %w", err))

						return
					}

					gid, ok := stat.Sys().(*syscall.Stat_t)
					assert.True(t, ok)

					assert.Equal(t, tt.conf.OpenVpn.Passthrough.SocketGroup, strconv.Itoa(int(gid.Gid)))
					assert.Equal(t, os.FileMode(tt.conf.OpenVpn.Passthrough.SocketMode), stat.Mode().Perm())
				} else {
					testutils.SendMessage(t, passThroughConn, "quit")
				}

				cancel(nil)
			}()

			<-ctx.Done()

			openVPNClient.Shutdown()
			wg.Wait()

			if err := context.Cause(ctx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
				require.NoError(t, err)
			}
		})
	}
}
