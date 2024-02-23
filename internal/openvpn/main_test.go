package openvpn_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/storage"
	"github.com/jkroepke/openvpn-auth-oauth2/pkg/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/nettest"
)

func TestClientInvalidServer(t *testing.T) {
	t.Parallel()

	logger := testutils.NewTestLogger()
	conf := config.Config{
		HTTP: config.HTTP{
			BaseURL: &url.URL{Scheme: "http", Host: "localhost"},
			Secret:  testutils.Secret,
		},
		OpenVpn: config.OpenVpn{
			Addr:   &url.URL{Scheme: "tcp", Host: "0.0.0.0:1"},
			Bypass: config.OpenVpnBypass{CommonNames: make([]string, 0)},
		},
	}
	storageClient := storage.New(testutils.Secret, time.Hour)
	provider := oauth2.New(logger.Logger, conf, storageClient)
	client := openvpn.NewClient(context.Background(), logger.Logger, conf, provider)
	err := client.Connect()
	require.Error(t, err)
	assert.Equal(t, "unable to connect to openvpn management interface tcp://0.0.0.0:1: dial tcp 0.0.0.0:1: connect: connection refused", err.Error())
}

func TestClientFull(t *testing.T) {
	t.Parallel()

	logger := testutils.NewTestLogger()

	confs := []struct {
		name   string
		conf   config.Config
		client string
		expect string
		err    error
	}{
		{
			name: "without password",
			conf: config.Config{
				HTTP: config.HTTP{
					BaseURL: &url.URL{Scheme: "http", Host: "localhost"},
					Secret:  testutils.Secret,
				},
				OpenVpn: config.OpenVpn{
					CommonName: config.OpenVPNCommonName{
						EnvironmentVariableName: "common_name",
					},
					Bypass: config.OpenVpnBypass{CommonNames: make([]string, 0)},
				},
			},
			client: ">CLIENT:CONNECT,1,2\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END\r\n",
			expect: "client-pending-auth 1 2 \"WEB_AUTH::",
		},
		{
			"with password",
			config.Config{
				HTTP: config.HTTP{
					BaseURL: &url.URL{Scheme: "http", Host: "localhost"},
					Secret:  testutils.Secret,
				},
				OpenVpn: config.OpenVpn{
					CommonName: config.OpenVPNCommonName{
						EnvironmentVariableName: "common_name",
					},
					Bypass:   config.OpenVpnBypass{CommonNames: make([]string, 0)},
					Password: "password",
				},
			},
			">CLIENT:CONNECT,1,2\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END\r\n",
			"client-pending-auth 1 2 \"WEB_AUTH::",
			nil,
		},
		{
			name: "with username",
			conf: config.Config{
				HTTP: config.HTTP{
					BaseURL: &url.URL{Scheme: "http", Host: "localhost"},
					Secret:  testutils.Secret,
				},
				OpenVpn: config.OpenVpn{
					CommonName: config.OpenVPNCommonName{
						EnvironmentVariableName: "username",
					},
					Bypass: config.OpenVpnBypass{CommonNames: make([]string, 0)},
				},
			},
			client: ">CLIENT:CONNECT,1,2\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,username=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END\r\n",
			expect: "client-pending-auth 1 2 \"WEB_AUTH::",
		},
		{
			"with invalid state",
			config.Config{
				HTTP: config.HTTP{
					BaseURL: &url.URL{Scheme: "http", Host: "localhost"},
					Secret:  "012345678910111",
				},
				OpenVpn: config.OpenVpn{
					CommonName: config.OpenVPNCommonName{
						EnvironmentVariableName: "common_name",
					},
					Bypass:   config.OpenVpnBypass{CommonNames: make([]string, 0)},
					Password: "password",
				},
			},
			">CLIENT:CONNECT,1,2\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END\r\n",
			"",
			errors.New("OpenVPN management error: error encoding state: encrypt aes: crypto/aes: invalid key size 15"),
		},
		{
			"client without IV_SSO",
			config.Config{
				HTTP: config.HTTP{
					BaseURL: &url.URL{Scheme: "http", Host: "localhost"},
					Secret:  testutils.Secret,
				},
				OpenVpn: config.OpenVpn{
					CommonName: config.OpenVPNCommonName{
						EnvironmentVariableName: "common_name",
					},
					Bypass:   config.OpenVpnBypass{CommonNames: make([]string, 0)},
					Password: "password",
				},
			},
			">CLIENT:CONNECT,0,1\r\n>CLIENT:ENV,daemon=0\r\n>CLIENT:ENV,END\r\n",
			"client-deny 0 1 \"OpenVPN Client does not support SSO authentication via webauth\"",
			nil,
		},
		{
			"client bypass",
			config.Config{
				HTTP: config.HTTP{
					BaseURL: &url.URL{Scheme: "http", Host: "localhost"},
					Secret:  testutils.Secret,
				},
				OpenVpn: config.OpenVpn{
					CommonName: config.OpenVPNCommonName{
						EnvironmentVariableName: "common_name",
					},
					Bypass:   config.OpenVpnBypass{CommonNames: []string{"bypass"}},
					Password: "password",
				},
			},
			">CLIENT:CONNECT,0,1\r\n>CLIENT:ENV,common_name=bypass\r\n>CLIENT:ENV,END\r\n",
			"client-auth-nt 0 1",
			nil,
		},
		{
			"client established",
			config.Config{
				HTTP: config.HTTP{
					BaseURL: &url.URL{Scheme: "http", Host: "localhost"},
					Secret:  testutils.Secret,
				},
				OpenVpn: config.OpenVpn{
					CommonName: config.OpenVPNCommonName{
						EnvironmentVariableName: "common_name",
					},
					Bypass:   config.OpenVpnBypass{CommonNames: []string{"bypass"}},
					Password: "password",
				},
			},
			">CLIENT:ESTABLISHED,0\r\n>CLIENT:ENV,common_name=bypass\r\n>CLIENT:ENV,END\r\n",
			"",
			nil,
		},
		{
			"client disconnected",
			config.Config{
				HTTP: config.HTTP{
					BaseURL: &url.URL{Scheme: "http", Host: "localhost"},
					Secret:  testutils.Secret,
				},
				OpenVpn: config.OpenVpn{
					CommonName: config.OpenVPNCommonName{
						EnvironmentVariableName: "common_name",
					},
					Bypass:   config.OpenVpnBypass{CommonNames: []string{"bypass"}},
					Password: "password",
				},
			},
			">CLIENT:DISCONNECT,0\r\n>CLIENT:ENV,common_name=bypass\r\n>CLIENT:ENV,END\r\n",
			"",
			nil,
		},
		{
			"client invalid reason",
			config.Config{
				HTTP: config.HTTP{
					BaseURL: &url.URL{Scheme: "http", Host: "localhost"},
					Secret:  testutils.Secret,
				},
				OpenVpn: config.OpenVpn{
					CommonName: config.OpenVPNCommonName{
						EnvironmentVariableName: "common_name",
					},
					Bypass:   config.OpenVpnBypass{CommonNames: []string{"bypass"}},
					Password: "password",
				},
			},
			">CLIENT:FOO,0\r\n>CLIENT:ENV,common_name=bypass\r\n>CLIENT:ENV,END\r\n",
			"",
			//nolint:revive
			errors.New("OpenVPN management error: unable to parse client reason from message: >CLIENT:FOO,0\r\n>CLIENT:ENV,common_name=bypass\r\n>CLIENT:ENV,END\r\n"),
		},
	}

	for _, tt := range confs {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			managementInterface, err := nettest.NewLocalListener("tcp")
			require.NoError(t, err)

			defer managementInterface.Close()

			tt.conf.OpenVpn.Addr = &url.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}

			storageClient := storage.New(testutils.Secret, time.Hour)
			provider := oauth2.New(logger.Logger, tt.conf, storageClient)
			client := openvpn.NewClient(context.Background(), logger.Logger, tt.conf, provider)

			wg := sync.WaitGroup{}
			wg.Add(1)

			go func() {
				defer wg.Done()

				conn, err := managementInterface.Accept()
				require.NoError(t, err) //nolint:testifylint

				defer conn.Close()

				reader := bufio.NewReader(conn)

				if tt.conf.OpenVpn.Password != "" {
					testutils.SendAndExpectMessage(t, conn, reader, "ENTER PASSWORD:", tt.conf.OpenVpn.Password.String())
					testutils.SendMessage(t, conn, "SUCCESS: password is correct")
				}

				testutils.ExpectVersionAndReleaseHold(t, conn, reader)
				testutils.SendMessage(t, conn, tt.client)

				if tt.err != nil {
					_, _ = reader.ReadString('\n')

					return
				} else if tt.expect == "" {
					return
				}

				auth := testutils.ReadLine(t, conn, reader)

				if strings.Contains(tt.expect, "WEB_AUTH") {
					assert.Contains(t, auth, tt.expect)
				} else {
					assert.Equal(t, tt.expect, auth)
				}

				testutils.SendMessage(t, conn, "SUCCESS: %s command succeeded\r\n", strings.SplitN(auth, " ", 2)[0])

				if strings.Contains(auth, "client-deny") {
					testutils.SendMessage(t, conn, ">CLIENT:DISCONNECT,0\r\n>CLIENT:ENV,END")
				} else if strings.Contains(auth, "WEB_AUTH::") {
					matches := regexp.MustCompile(`state=(.+)"`).FindStringSubmatch(auth)
					assert.Len(t, matches, 2)

					sessionState := state.NewEncoded(matches[1])
					err := sessionState.Decode(tt.conf.HTTP.Secret.String())
					require.NoError(t, err) //nolint:testifylint

					assert.Equal(t, uint64(1), sessionState.Client.Cid)
					assert.Equal(t, uint64(2), sessionState.Client.Kid)
					assert.Equal(t, "test", sessionState.CommonName)
					assert.Equal(t, "127.0.0.1", sessionState.Ipaddr)
				}
			}()

			err = client.Connect()
			if tt.err != nil {
				require.Error(t, err)
				assert.Equal(t, tt.err.Error(), err.Error())
			} else {
				wg.Wait()

				if err != nil && !errors.Is(err, io.EOF) {
					require.NoError(t, err)
				}
			}

			client.Shutdown()
		})
	}
}

func TestClientInvalidPassword(t *testing.T) {
	t.Parallel()

	logger := testutils.NewTestLogger()

	managementInterface, err := nettest.NewLocalListener("tcp")
	require.NoError(t, err)

	defer managementInterface.Close()

	conf := config.Config{
		HTTP: config.HTTP{
			BaseURL: &url.URL{Scheme: "http", Host: "localhost"},
			Secret:  testutils.Secret,
		},
		OpenVpn: config.OpenVpn{
			Addr:     &url.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()},
			Bypass:   config.OpenVpnBypass{CommonNames: make([]string, 0)},
			Password: "invalid",
		},
	}

	storageClient := storage.New(testutils.Secret, time.Hour)
	provider := oauth2.New(logger.Logger, conf, storageClient)
	client := openvpn.NewClient(context.Background(), logger.Logger, conf, provider)

	go func() {
		conn, err := managementInterface.Accept()
		require.NoError(t, err) //nolint:testifylint

		defer conn.Close()
		reader := bufio.NewReader(conn)

		testutils.SendMessage(t, conn, "ENTER PASSWORD:")
		testutils.ExpectMessage(t, conn, reader, conf.OpenVpn.Password.String())
		testutils.SendMessage(t, conn, "ERROR: bad password")
	}()

	err = client.Connect()

	require.Error(t, err)
	assert.Equal(t, "unable to connect to openvpn management interface: invalid password", err.Error())

	client.Shutdown()
}

func TestClientInvalidVersion(t *testing.T) {
	t.Parallel()

	logger := testutils.NewTestLogger()

	conf := config.Config{
		HTTP: config.HTTP{
			BaseURL: &url.URL{Scheme: "http", Host: "localhost"},
			Secret:  testutils.Secret,
		},
		OpenVpn: config.OpenVpn{
			Bypass: config.OpenVpnBypass{CommonNames: make([]string, 0)},
		},
	}

	versions := []struct {
		name    string
		version string
		err     string
	}{
		{
			"invalid parts",
			"OpenVPN Version: OpenVPN Mock\r\nEND\r\n",
			"OpenVPN management error: unexpected response from version command: OpenVPN Version: OpenVPN Mock\r\nEND\r\n",
		},
		{
			"invalid version",
			"OpenVPN Version: OpenVPN Mock\r\nManagement Interface Version:\r\nEND\r\n",
			`OpenVPN management error: unable to parse openvpn management interface version: strconv.Atoi: parsing ":": invalid syntax`,
		},
		{
			"version to low",
			"OpenVPN Version: OpenVPN Mock\r\nManagement Interface Version: 4\r\nEND\r\n",
			`OpenVPN management error: openvpn-auth-oauth2 requires OpenVPN management interface version 5 or higher`,
		},
	}

	for _, tt := range versions {
		tt, conf := tt, conf

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			managementInterface, err := nettest.NewLocalListener("tcp")
			require.NoError(t, err)

			defer managementInterface.Close()

			conf.OpenVpn.Addr = &url.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}

			storageClient := storage.New(testutils.Secret, time.Hour)
			provider := oauth2.New(logger.Logger, conf, storageClient)
			openVPNClient := openvpn.NewClient(context.Background(), logger.Logger, conf, provider)

			ctx, cancel := context.WithCancelCause(context.Background())
			wg := sync.WaitGroup{}
			wg.Add(2)

			go func() {
				defer wg.Done()

				managementInterfaceConn, err := managementInterface.Accept()
				if err != nil {
					cancel(fmt.Errorf("accepting connection: %w", err))

					return
				}

				defer managementInterfaceConn.Close()
				reader := bufio.NewReader(managementInterfaceConn)

				testutils.SendAndExpectMessage(t, managementInterfaceConn, reader,
					">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info",
					"version",
				)

				testutils.SendMessage(t, managementInterfaceConn, tt.version)

				<-ctx.Done()
			}()

			go func() {
				defer wg.Done()

				err := openVPNClient.Connect()
				if err != nil {
					cancel(err)

					return
				}

				cancel(nil)
			}()

			<-ctx.Done()

			wg.Wait()
			openVPNClient.Shutdown()

			err = context.Cause(ctx)

			require.Error(t, err)
			assert.Equal(t, tt.err, err.Error())
		})
	}
}

func TestSIGHUP(t *testing.T) {
	t.Parallel()

	logger := testutils.NewTestLogger()

	conf := config.Config{
		HTTP: config.HTTP{
			BaseURL: &url.URL{Scheme: "http", Host: "localhost"},
			Secret:  testutils.Secret,
		},
		OpenVpn: config.OpenVpn{
			Bypass: config.OpenVpnBypass{CommonNames: make([]string, 0)},
		},
	}

	managementInterface, err := nettest.NewLocalListener("tcp")
	require.NoError(t, err)

	defer managementInterface.Close()

	conf.OpenVpn.Addr = &url.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}

	storageClient := storage.New(testutils.Secret, time.Hour)
	provider := oauth2.New(logger.Logger, conf, storageClient)
	client := openvpn.NewClient(context.Background(), logger.Logger, conf, provider)

	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer wg.Done()

		conn, err := managementInterface.Accept()
		require.NoError(t, err) //nolint:testifylint

		defer conn.Close()
		reader := bufio.NewReader(conn)

		testutils.ExpectVersionAndReleaseHold(t, conn, reader)

		for i := 0; i < 10; i++ {
			testutils.SendAndExpectMessage(t, conn, reader,
				">HOLD:Waiting for hold release:0",
				"hold release",
			)
		}
	}()

	require.NoError(t, client.Connect())

	wg.Wait()
	client.Shutdown()
}

func TestDeadLocks(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		message string
	}{
		{
			name:    "explicit-exit-notify",
			message: ">NOTIFY:info,remote-exit,EXIT",
		},
		{
			name:    "empty-lines",
			message: "\r\n",
		},
	} {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := testutils.NewTestLogger()

			conf := config.Config{
				HTTP: config.HTTP{
					BaseURL: &url.URL{Scheme: "http", Host: "localhost"},
					Secret:  testutils.Secret,
				},
				OpenVpn: config.OpenVpn{
					Bypass: config.OpenVpnBypass{CommonNames: make([]string, 0)},
				},
			}

			managementInterface, err := nettest.NewLocalListener("tcp")
			require.NoError(t, err)

			defer managementInterface.Close()

			conf.OpenVpn.Addr = &url.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}

			storageClient := storage.New(testutils.Secret, time.Hour)
			provider := oauth2.New(logger.Logger, conf, storageClient)
			client := openvpn.NewClient(context.Background(), logger.Logger, conf, provider)

			wg := sync.WaitGroup{}
			wg.Add(1)

			go func() {
				defer wg.Done()

				conn, err := managementInterface.Accept()
				require.NoError(t, err) //nolint:testifylint

				defer conn.Close()
				reader := bufio.NewReader(conn)

				testutils.ExpectVersionAndReleaseHold(t, conn, reader)

				for i := 0; i < 12; i++ {
					testutils.SendMessage(t, conn, tt.message)
				}
			}()

			require.NoError(t, client.Connect())

			wg.Wait()
			client.Shutdown()
		})
	}
}

func TestInvalidCommandResponses(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		message string
	}{
		{
			name:    "empty SUCCESS",
			message: "SUCCESS:   ",
		},
		{
			name:    "empty ERROR",
			message: "ERROR:    ",
		},
	} {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := testutils.NewTestLogger()

			conf := config.Config{
				HTTP: config.HTTP{
					BaseURL: &url.URL{Scheme: "http", Host: "localhost"},
					Secret:  testutils.Secret,
				},
				OpenVpn: config.OpenVpn{
					Bypass: config.OpenVpnBypass{CommonNames: make([]string, 0)},
				},
			}

			managementInterface, err := nettest.NewLocalListener("tcp")
			require.NoError(t, err)

			defer managementInterface.Close()

			conf.OpenVpn.Addr = &url.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}

			storageClient := storage.New(testutils.Secret, time.Hour)
			provider := oauth2.New(logger.Logger, conf, storageClient)
			client := openvpn.NewClient(context.Background(), logger.Logger, conf, provider)

			wg := sync.WaitGroup{}
			wg.Add(1)

			go func() {
				defer wg.Done()

				conn, err := managementInterface.Accept()
				require.NoError(t, err) //nolint:testifylint

				defer conn.Close()
				reader := bufio.NewReader(conn)

				testutils.ExpectVersionAndReleaseHold(t, conn, reader)
				testutils.SendAndExpectMessage(t, conn, reader,
					">HOLD:Waiting for hold release:0",
					"hold release",
				)

				testutils.SendMessage(t, conn, tt.message)
			}()

			require.NoError(t, client.Connect())

			wg.Wait()
			client.Shutdown()
		})
	}
}
