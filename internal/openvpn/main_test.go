package openvpn_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn/connection"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/tokenstorage"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/nettest"
)

func TestClientInvalidServer(t *testing.T) {
	t.Parallel()

	logger := testutils.NewTestLogger()
	conf := config.Config{
		HTTP: config.HTTP{
			BaseURL: &config.URL{Scheme: "http", Host: "localhost"},
			Secret:  testutils.Secret,
		},
		OpenVpn: config.OpenVpn{
			Addr:   &config.URL{Scheme: "tcp", Host: "127.0.0.1:1"},
			Bypass: config.OpenVpnBypass{CommonNames: make([]string, 0)},
		},
	}

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	tokenStorage := tokenstorage.NewInMemory(ctx, testutils.Secret, time.Hour)
	_, openVPNClient := testutils.SetupOpenVPNOAuth2Clients(ctx, t, conf, logger.Logger, http.DefaultClient, tokenStorage)

	err := openVPNClient.Connect(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unable to connect to openvpn management interface tcp://127.0.0.1:1: dial tcp 127.0.0.1:1: connect")
}

func TestClientFull(t *testing.T) {
	t.Parallel()

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
					BaseURL: &config.URL{Scheme: "http", Host: "localhost"},
					Secret:  testutils.Secret,
				},
				OpenVpn: config.OpenVpn{
					CommonName: config.OpenVPNCommonName{
						EnvironmentVariableName: "common_name",
					},
					Bypass: config.OpenVpnBypass{CommonNames: make([]string, 0)},
				},
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{
						IPAddr: true,
					},
				},
			},
			client: ">CLIENT:CONNECT,1,2\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END\r\n",
			expect: "client-pending-auth 1 2 \"WEB_AUTH::",
		},
		{
			"with password",
			config.Config{
				HTTP: config.HTTP{
					BaseURL: &config.URL{Scheme: "http", Host: "localhost"},
					Secret:  testutils.Secret,
				},
				OpenVpn: config.OpenVpn{
					CommonName: config.OpenVPNCommonName{
						EnvironmentVariableName: "common_name",
					},
					Bypass:   config.OpenVpnBypass{CommonNames: make([]string, 0)},
					Password: "password",
				},
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{
						IPAddr: true,
					},
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
					BaseURL: &config.URL{Scheme: "http", Host: "localhost"},
					Secret:  testutils.Secret,
				},
				OpenVpn: config.OpenVpn{
					CommonName: config.OpenVPNCommonName{
						EnvironmentVariableName: "username",
					},
					Bypass: config.OpenVpnBypass{CommonNames: make([]string, 0)},
				},
				OAuth2: config.OAuth2{
					Validate: config.OAuth2Validate{
						IPAddr: true,
					},
				},
			},
			client: ">CLIENT:CONNECT,1,2\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,username=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END\r\n",
			expect: "client-pending-auth 1 2 \"WEB_AUTH::",
		},
		{
			"with invalid state",
			config.Config{
				HTTP: config.HTTP{
					BaseURL: &config.URL{Scheme: "http", Host: "localhost"},
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
			nil,
		},
		{
			"client without IV_SSO",
			config.Config{
				HTTP: config.HTTP{
					BaseURL: &config.URL{Scheme: "http", Host: "localhost"},
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
			"to long base url",
			config.Config{
				HTTP: config.HTTP{
					BaseURL: &config.URL{Scheme: "http", Host: "localhost", Path: strings.Repeat("a", 255)},
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
			`client-deny 1 2 "internal error"`,
			nil,
		},
		{
			"client bypass",
			config.Config{
				HTTP: config.HTTP{
					BaseURL: &config.URL{Scheme: "http", Host: "localhost"},
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
			"client password mask",
			config.Config{
				HTTP: config.HTTP{
					BaseURL: &config.URL{Scheme: "http", Host: "localhost"},
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
			">CLIENT:CONNECT,0,1\r\n>CLIENT:ENV,common_name=bypass\r\nCLIENT:ENV,password=important value\n>CLIENT:ENV,END\r\n",
			"client-auth-nt 0 1",
			nil,
		},
		{
			"client established",
			config.Config{
				HTTP: config.HTTP{
					BaseURL: &config.URL{Scheme: "http", Host: "localhost"},
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
					BaseURL: &config.URL{Scheme: "http", Host: "localhost"},
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
			"client invalid reason 1",
			config.Config{
				HTTP: config.HTTP{
					BaseURL: &config.URL{Scheme: "http", Host: "localhost"},
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
			connection.ErrParseErrorClientReason,
		},
		{
			"client invalid reason 2",
			config.Config{
				HTTP: config.HTTP{
					BaseURL: &config.URL{Scheme: "http", Host: "localhost"},
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
			">CLIENT:CONNECT1,0,1\r\n>CLIENT:ENV,common_name=bypass\r\n>CLIENT:ENV,END\r\n",
			"",
			openvpn.ErrUnknownClientReason,
		},
	}

	for _, tt := range confs {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := testutils.NewTestLogger()

			managementInterface, err := nettest.NewLocalListener("tcp")
			require.NoError(t, err)

			t.Cleanup(func() {
				require.NoError(t, managementInterface.Close())
			})

			tt.conf.OpenVpn.Addr = &config.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}

			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)

			tokenStorage := tokenstorage.NewInMemory(ctx, testutils.Secret, time.Hour)
			_, openVPNClient := testutils.SetupOpenVPNOAuth2Clients(ctx, t, tt.conf, logger.Logger, http.DefaultClient, tokenStorage)

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
					assert.Equal(t, tt.expect, auth, logger.String())
				}

				if strings.Contains(tt.client, "CLIENT:ENV,password=") {
					assert.Contains(t, logger.String(), `CLIENT:ENV,password=***`, logger.String())
				}

				testutils.SendMessage(t, conn, "SUCCESS: %s command succeeded\r\n", strings.SplitN(auth, " ", 2)[0])

				if strings.Contains(auth, "client-deny") {
					testutils.SendMessage(t, conn, ">CLIENT:DISCONNECT,0\r\n>CLIENT:ENV,END")
				} else if strings.Contains(auth, "WEB_AUTH::") {
					matches := regexp.MustCompile(`state=(.+)"`).FindStringSubmatch(auth)
					assert.Len(t, matches, 2)

					sessionState, err := state.NewWithEncodedToken(matches[1], tt.conf.HTTP.Secret.String())
					require.NoError(t, err) //nolint:testifylint

					assert.Equal(t, uint64(1), sessionState.Client.CID)
					assert.Equal(t, uint64(2), sessionState.Client.KID)
					assert.Equal(t, "test", sessionState.CommonName)
					assert.Equal(t, "127.0.0.1", sessionState.IPAddr)
				}
			}()

			err = openVPNClient.Connect(t.Context())
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
			} else {
				wg.Wait()

				if err != nil && !errors.Is(err, io.EOF) {
					require.NoError(t, err)
				}
			}
		})
	}
}

func TestClientInvalidPassword(t *testing.T) {
	t.Parallel()

	logger := testutils.NewTestLogger()

	managementInterface, err := nettest.NewLocalListener("tcp")
	require.NoError(t, err)

	t.Cleanup(func() {
		managementInterface.Close()
	})

	conf := config.Config{
		HTTP: config.HTTP{
			BaseURL: &config.URL{Scheme: "http", Host: "localhost"},
			Secret:  testutils.Secret,
		},
		OpenVpn: config.OpenVpn{
			Addr:     &config.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()},
			Bypass:   config.OpenVpnBypass{CommonNames: make([]string, 0)},
			Password: "invalid",
		},
	}

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	tokenStorage := tokenstorage.NewInMemory(ctx, testutils.Secret, time.Hour)
	_, openVPNClient := testutils.SetupOpenVPNOAuth2Clients(ctx, t, conf, logger.Logger, http.DefaultClient, tokenStorage)

	go func() {
		conn, err := managementInterface.Accept()
		require.NoError(t, err) //nolint:testifylint

		defer conn.Close()
		reader := bufio.NewReader(conn)

		testutils.SendMessage(t, conn, "ENTER PASSWORD:")
		testutils.ExpectMessage(t, conn, reader, conf.OpenVpn.Password.String())
		testutils.SendMessage(t, conn, "ERROR: bad password")
	}()

	err = openVPNClient.Connect(t.Context())

	require.EqualError(t, err, "openvpn management error: unable to connect to openvpn management interface: invalid password")
}

func TestClientInvalidVersion(t *testing.T) {
	t.Parallel()

	logger := testutils.NewTestLogger()

	conf := config.Config{
		HTTP: config.HTTP{
			BaseURL: &config.URL{Scheme: "http", Host: "localhost"},
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
			"openvpn management error: unexpected response from version command: OpenVPN Version: OpenVPN Mock\r\nEND\r\n",
		},
		{
			"invalid version",
			"OpenVPN Version: OpenVPN Mock\r\nManagement Interface Version:\r\nEND\r\n",
			`openvpn management error: unable to parse openvpn management interface version: strconv.Atoi: parsing ":": invalid syntax`,
		},
		{
			"version to low",
			"OpenVPN Version: OpenVPN Mock\r\nManagement Interface Version: 4\r\nEND\r\n",
			`openvpn management error: openvpn-auth-oauth2 requires OpenVPN management interface version 5 or higher`,
		},
	}

	for _, tt := range versions {
		t.Run(tt.name, func(t *testing.T) {
			conf := conf

			t.Parallel()

			managementInterface, err := nettest.NewLocalListener("tcp")
			require.NoError(t, err)

			t.Cleanup(func() {
				managementInterface.Close()
			})

			conf.OpenVpn.Addr = &config.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}

			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)

			tokenStorage := tokenstorage.NewInMemory(ctx, testutils.Secret, time.Hour)
			_, openVPNClient := testutils.SetupOpenVPNOAuth2Clients(ctx, t, conf, logger.Logger, http.DefaultClient, tokenStorage)

			wg := sync.WaitGroup{}
			wg.Add(1)

			errCh := make(chan error, 1)

			go func() {
				defer wg.Done()

				errCh <- openVPNClient.Connect(ctx)
			}()

			managementInterfaceConn, err := managementInterface.Accept()
			require.NoError(t, err)

			t.Cleanup(func() {
				managementInterfaceConn.Close()
			})

			reader := bufio.NewReader(managementInterfaceConn)

			testutils.SendAndExpectMessage(t, managementInterfaceConn, reader,
				">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info",
				"version",
			)

			testutils.SendMessage(t, managementInterfaceConn, tt.version)

			wg.Wait()

			err = <-errCh

			require.EqualError(t, err, tt.err, tt.err)
		})
	}
}

func TestSIGHUP(t *testing.T) {
	t.Parallel()

	logger := testutils.NewTestLogger()

	conf := config.Config{
		HTTP: config.HTTP{
			BaseURL: &config.URL{Scheme: "http", Host: "localhost"},
			Secret:  testutils.Secret,
		},
		OpenVpn: config.OpenVpn{
			Bypass: config.OpenVpnBypass{CommonNames: make([]string, 0)},
		},
	}

	managementInterface, err := nettest.NewLocalListener("tcp")
	require.NoError(t, err)

	t.Cleanup(func() {
		managementInterface.Close()
	})

	conf.OpenVpn.Addr = &config.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	tokenStorage := tokenstorage.NewInMemory(ctx, testutils.Secret, time.Hour)
	_, openVPNClient := testutils.SetupOpenVPNOAuth2Clients(ctx, t, conf, logger.Logger, http.DefaultClient, tokenStorage)

	wg := sync.WaitGroup{}
	wg.Add(2)

	errCh := make(chan error, 2)

	go func() {
		defer wg.Done()

		conn, err := managementInterface.Accept()
		require.NoError(t, err) //nolint:testifylint

		defer conn.Close()
		reader := bufio.NewReader(conn)

		testutils.ExpectVersionAndReleaseHold(t, conn, reader)

		for range 10 {
			testutils.SendAndExpectMessage(t, conn, reader,
				">HOLD:Waiting for hold release:0",
				"hold release",
			)
		}
	}()

	go func() {
		defer wg.Done()

		errCh <- openVPNClient.Connect(ctx)
	}()

	require.NoError(t, <-errCh)

	wg.Wait()
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := testutils.NewTestLogger()

			conf := config.Config{
				HTTP: config.HTTP{
					BaseURL: &config.URL{Scheme: "http", Host: "localhost"},
					Secret:  testutils.Secret,
				},
				OpenVpn: config.OpenVpn{
					Bypass: config.OpenVpnBypass{CommonNames: make([]string, 0)},
				},
			}

			managementInterface, err := nettest.NewLocalListener("tcp")
			require.NoError(t, err)

			t.Cleanup(func() {
				managementInterface.Close()
			})

			conf.OpenVpn.Addr = &config.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}

			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)

			tokenStorage := tokenstorage.NewInMemory(ctx, testutils.Secret, time.Hour)
			_, openVPNClient := testutils.SetupOpenVPNOAuth2Clients(ctx, t, conf, logger.Logger, http.DefaultClient, tokenStorage)

			wg := sync.WaitGroup{}
			wg.Add(2)

			errCh := make(chan error, 2)

			go func() {
				defer wg.Done()

				conn, err := managementInterface.Accept()
				if err != nil {
					errCh <- fmt.Errorf("accepting connection: %w", err)

					return
				}

				defer conn.Close()
				reader := bufio.NewReader(conn)

				testutils.ExpectVersionAndReleaseHold(t, conn, reader)

				for range 12 {
					testutils.SendMessage(t, conn, tt.message)
				}
			}()

			go func() {
				defer wg.Done()

				errCh <- openVPNClient.Connect(ctx)
			}()

			require.NoError(t, <-errCh)

			wg.Wait()
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			logger := testutils.NewTestLogger()

			conf := config.Config{
				HTTP: config.HTTP{
					BaseURL: &config.URL{Scheme: "http", Host: "localhost"},
					Secret:  testutils.Secret,
				},
				OpenVpn: config.OpenVpn{
					Bypass: config.OpenVpnBypass{CommonNames: make([]string, 0)},
				},
			}

			managementInterface, err := nettest.NewLocalListener("tcp")
			require.NoError(t, err)

			t.Cleanup(func() {
				managementInterface.Close()
			})

			conf.OpenVpn.Addr = &config.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}

			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)

			tokenStorage := tokenstorage.NewInMemory(ctx, testutils.Secret, time.Hour)
			_, openVPNClient := testutils.SetupOpenVPNOAuth2Clients(ctx, t, conf, logger.Logger, http.DefaultClient, tokenStorage)

			wg := sync.WaitGroup{}
			wg.Add(2)

			errCh := make(chan error, 2)

			go func() {
				defer wg.Done()

				conn, err := managementInterface.Accept()
				if err != nil {
					errCh <- fmt.Errorf("accepting connection: %w", err)

					return
				}

				defer conn.Close()
				reader := bufio.NewReader(conn)

				testutils.ExpectVersionAndReleaseHold(t, conn, reader)
				testutils.SendAndExpectMessage(t, conn, reader,
					">HOLD:Waiting for hold release:0",
					"hold release",
				)

				testutils.SendMessage(t, conn, tt.message)
			}()

			go func() {
				defer wg.Done()

				errCh <- openVPNClient.Connect(ctx)
			}()

			require.NoError(t, <-errCh)

			wg.Wait()
		})
	}
}
