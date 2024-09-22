//go:build !windows

package openvpn_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/nettest"
)

func TestPassthroughFull(t *testing.T) {
	t.Parallel()

	logger := testutils.NewTestLogger()

	conf := config.Defaults
	conf.HTTP.Secret = testutils.Secret
	conf.OpenVpn.Passthrough.Enabled = true

	configs := []struct {
		name   string
		scheme string
		conf   config.Config
	}{
		{
			name:   "tcp default",
			scheme: openvpn.SchemeTCP,
			conf:   conf,
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

	for _, tt := range configs {
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

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			storageClient := storage.New(ctx, testutils.Secret, time.Hour)
			provider := oauth2.New(logger.Logger, tt.conf, storageClient, http.DefaultClient)
			openVPNClient := openvpn.New(ctx, logger.Logger, tt.conf, provider, nil)

			defer openVPNClient.Shutdown()

			wg := sync.WaitGroup{}

			wg.Add(1)

			go func() {
				defer wg.Done()

				managementInterfaceConn, err := managementInterface.Accept()
				if err != nil {
					assert.NoError(t, fmt.Errorf("accepting connection: %w", err))
					cancel()

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
				testutils.SendMessage(t, managementInterfaceConn, "")
				testutils.SendMessage(t, managementInterfaceConn, "\r\n")

				var message string

				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						if !errors.Is(err, io.EOF) {
							assert.NoError(t, err)
						}

						cancel()

						return
					}

					line = strings.TrimSpace(line)

					if line == "exit" {
						cancel()

						break
					}

					switch line {
					case "help":
						message = OpenVPNManagementInterfaceCommandResultHelp
					case "status":
						message = OpenVPNManagementInterfaceCommandResultStatus
					case "status 2":
						message = OpenVPNManagementInterfaceCommandResultStatus2
					case "status 3":
						message = OpenVPNManagementInterfaceCommandResultStatus3
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
					assert.NoError(t, fmt.Errorf("connecting: %w", err))
					cancel()

					return
				}

				<-ctx.Done()
			}()

			wg.Add(1)

			go func() {
				defer wg.Done()
				defer cancel()

				var passThroughConn net.Conn

				for range 100 {
					passThroughConn, err = net.DialTimeout(passThroughInterface.Addr().Network(), passThroughInterface.Addr().String(), time.Second)
					if err == nil {
						break
					}

					time.Sleep(50 * time.Millisecond)
				}

				if !assert.NoError(t, err) {
					return
				}

				passThroughReader := bufio.NewReader(passThroughConn)

				if tt.conf.OpenVpn.Passthrough.Password != "" {
					buf := make([]byte, 15)

					_, err = passThroughConn.Read(buf)
					if !assert.NoError(t, err) {
						return
					}

					assert.Equal(t, "ENTER PASSWORD:", string(buf))

					if strings.Contains(tt.name, "invalid") {
						testutils.SendAndExpectMessage(t, passThroughConn, passThroughReader,
							"invalid",
							"ERROR: bad password",
						)

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

					testutils.SendAndExpectMessage(t, passThroughConn, passThroughReader,
						"status 2",
						OpenVPNManagementInterfaceCommandResultStatus2,
					)

					testutils.SendAndExpectMessage(t, passThroughConn, passThroughReader,
						"status 3",
						OpenVPNManagementInterfaceCommandResultStatus3,
					)
				}

				for range 10 {
					testutils.SendAndExpectMessage(t, passThroughConn, passThroughReader,
						"help",
						OpenVPNManagementInterfaceCommandResultHelp,
					)
				}

				if tt.scheme == openvpn.SchemeUnix {
					testutils.SendMessage(t, passThroughConn, " exit ")

					stat, err := os.Stat(passThroughInterface.Addr().String())
					if !assert.NoError(t, err) {
						return
					}

					gid, ok := stat.Sys().(*syscall.Stat_t)
					assert.True(t, ok)

					assert.Equal(t, tt.conf.OpenVpn.Passthrough.SocketGroup, strconv.Itoa(int(gid.Gid)))
					assert.Equal(t, os.FileMode(tt.conf.OpenVpn.Passthrough.SocketMode), stat.Mode().Perm()) //nolint:gosec
				} else {
					testutils.SendMessage(t, passThroughConn, " quit ")
				}
			}()

			<-ctx.Done()

			openVPNClient.Shutdown()
			wg.Wait()
		})
	}
}
