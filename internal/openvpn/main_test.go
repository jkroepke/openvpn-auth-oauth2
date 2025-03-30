package openvpn_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn/connection"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/tokenstorage"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/nettest"
)

func TestClientInvalidServer(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

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

	tokenStorage := tokenstorage.NewInMemory(ctx, testutils.Secret, time.Hour)
	_, openVPNClient := testutils.SetupOpenVPNOAuth2Clients(ctx, t, conf, logger.Logger, http.DefaultClient, tokenStorage)

	err := openVPNClient.Connect(t.Context())
	require.Error(t, err)
	require.Contains(t, err.Error(), "unable to connect to openvpn management interface tcp://127.0.0.1:1: dial tcp 127.0.0.1:1: connect")
}

func TestClientFull(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)

			logger := testutils.NewTestLogger()

			managementInterface, err := nettest.NewLocalListener("tcp")
			require.NoError(t, err)

			t.Cleanup(func() {
				require.NoError(t, managementInterface.Close())
			})

			tc.conf.OpenVpn.Addr = &config.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}

			tokenStorage := tokenstorage.NewInMemory(ctx, testutils.Secret, time.Hour)
			_, openVPNClient := testutils.SetupOpenVPNOAuth2Clients(ctx, t, tc.conf, logger.Logger, http.DefaultClient, tokenStorage)

			managementInterfaceConn, errOpenVPNClientCh, err := testutils.ConnectToManagementInterface(t, managementInterface, openVPNClient)
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, managementInterfaceConn.Close())

				select {
				case err := <-errOpenVPNClientCh:
					if err != nil && !errors.Is(err, io.EOF) {
						if tc.err != nil {
							require.ErrorIs(t, err, tc.err)
						} else {
							require.NoError(t, err)
						}
					}
				case <-time.After(1 * time.Second):
					t.Fatalf("timeout waiting for connection to close. Logs:\n\n%s", logger.String())
				}
			})

			reader := bufio.NewReader(managementInterfaceConn)

			if tc.conf.OpenVpn.Password != "" {
				testutils.SendAndExpectMessage(t, managementInterfaceConn, reader, "ENTER PASSWORD:", tc.conf.OpenVpn.Password.String())
				testutils.SendMessage(t, managementInterfaceConn, "SUCCESS: password is correct")
			}

			testutils.ExpectVersionAndReleaseHold(t, managementInterfaceConn, reader)
			testutils.SendMessage(t, managementInterfaceConn, tc.client)

			if tc.err != nil {
				_, _ = reader.ReadString('\n')

				return
			} else if tc.expect == "" {
				return
			}

			auth := testutils.ReadLine(t, managementInterfaceConn, reader)

			if strings.Contains(tc.expect, "WEB_AUTH") {
				require.Contains(t, auth, tc.expect)
			} else {
				require.Equal(t, tc.expect, auth, logger.String())
			}

			if strings.Contains(tc.client, "CLIENT:ENV,password=") {
				require.Contains(t, logger.String(), `CLIENT:ENV,password=***`, logger.String())
			}

			testutils.SendMessage(t, managementInterfaceConn, "SUCCESS: %s command succeeded\r\n", strings.SplitN(auth, " ", 2)[0])

			if strings.Contains(auth, "client-deny") {
				testutils.SendMessage(t, managementInterfaceConn, ">CLIENT:DISCONNECT,0\r\n>CLIENT:ENV,END")
			} else if strings.Contains(auth, "WEB_AUTH::") {
				matches := regexp.MustCompile(`state=(.+)"`).FindStringSubmatch(auth)
				require.Len(t, matches, 2)

				sessionState, err := state.NewWithEncodedToken(matches[1], tc.conf.HTTP.Secret.String())
				require.NoError(t, err)

				require.Equal(t, uint64(1), sessionState.Client.CID)
				require.Equal(t, uint64(2), sessionState.Client.KID)
				require.Equal(t, "test", sessionState.CommonName)
				require.Equal(t, "127.0.0.1", sessionState.IPAddr)
			}
		})
	}
}

func TestClientInvalidPassword(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	logger := testutils.NewTestLogger()

	managementInterface, err := nettest.NewLocalListener("tcp")
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, managementInterface.Close())
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

	tokenStorage := tokenstorage.NewInMemory(ctx, testutils.Secret, time.Hour)
	_, openVPNClient := testutils.SetupOpenVPNOAuth2Clients(ctx, t, conf, logger.Logger, http.DefaultClient, tokenStorage)

	managementInterfaceConn, errOpenVPNClientCh, err := testutils.ConnectToManagementInterface(t, managementInterface, openVPNClient)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, managementInterfaceConn.Close())
	})

	reader := bufio.NewReader(managementInterfaceConn)

	testutils.SendMessage(t, managementInterfaceConn, "ENTER PASSWORD:")
	testutils.ExpectMessage(t, managementInterfaceConn, reader, conf.OpenVpn.Password.String())
	testutils.SendMessage(t, managementInterfaceConn, "ERROR: bad password")

	select {
	case err := <-errOpenVPNClientCh:
		require.ErrorIs(t, err, openvpn.ErrInvalidPassword)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for connection to close")
	}
}

func TestClientInvalidVersion(t *testing.T) {
	t.Parallel()

	conf := config.Config{
		HTTP: config.HTTP{
			BaseURL: &config.URL{Scheme: "http", Host: "localhost"},
			Secret:  testutils.Secret,
		},
		OpenVpn: config.OpenVpn{
			Bypass: config.OpenVpnBypass{CommonNames: make([]string, 0)},
		},
	}

	for _, tc := range []struct {
		name    string
		version string
		err     error
	}{
		{
			"invalid parts",
			"OpenVPN Version: OpenVPN Mock\r\nEND\r\n",
			openvpn.ErrUnexpectedResponseFromVersionCommand,
		},
		{
			"invalid version",
			"OpenVPN Version: OpenVPN Mock\r\nManagement Interface Version:\r\nEND\r\n",
			strconv.ErrSyntax,
		},
		{
			"version to low",
			"OpenVPN Version: OpenVPN Mock\r\nManagement Interface Version: 4\r\nEND\r\n",
			openvpn.ErrRequireManagementInterfaceVersion5,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)

			logger := testutils.NewTestLogger()

			conf := conf

			managementInterface, err := nettest.NewLocalListener("tcp")
			require.NoError(t, err)

			t.Cleanup(func() {
				require.NoError(t, managementInterface.Close())
			})

			conf.OpenVpn.Addr = &config.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}

			tokenStorage := tokenstorage.NewInMemory(ctx, testutils.Secret, time.Hour)
			_, openVPNClient := testutils.SetupOpenVPNOAuth2Clients(ctx, t, conf, logger.Logger, http.DefaultClient, tokenStorage)

			managementInterfaceConn, errOpenVPNClientCh, err := testutils.ConnectToManagementInterface(t, managementInterface, openVPNClient)
			require.NoError(t, err)

			reader := bufio.NewReader(managementInterfaceConn)

			testutils.SendAndExpectMessage(t, managementInterfaceConn, reader,
				">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info",
				"version",
			)

			testutils.SendMessage(t, managementInterfaceConn, tc.version)

			select {
			case err := <-errOpenVPNClientCh:
				require.ErrorIs(t, err, tc.err)
			case <-time.After(1 * time.Second):
				t.Fatalf("timeout waiting for connection to close. Logs:\n\n%s", logger.String())
			}
		})
	}
}

func TestHoldRelease(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

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
		require.NoError(t, managementInterface.Close())
	})

	conf.OpenVpn.Addr = &config.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}

	tokenStorage := tokenstorage.NewInMemory(ctx, testutils.Secret, time.Hour)
	_, openVPNClient := testutils.SetupOpenVPNOAuth2Clients(ctx, t, conf, logger.Logger, http.DefaultClient, tokenStorage)

	managementInterfaceConn, errOpenVPNClientCh, err := testutils.ConnectToManagementInterface(t, managementInterface, openVPNClient)
	require.NoError(t, err)

	reader := bufio.NewReader(managementInterfaceConn)

	testutils.ExpectVersionAndReleaseHold(t, managementInterfaceConn, reader)

	for range 10 {
		testutils.SendAndExpectMessage(t, managementInterfaceConn, reader,
			">HOLD:Waiting for hold release:0",
			"hold release",
		)
	}

	require.NoError(t, managementInterfaceConn.Close())

	select {
	case err := <-errOpenVPNClientCh:
		require.NoError(t, err)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for connection to close")
	}
}

func TestDeadLocks(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
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
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)

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
				require.NoError(t, managementInterface.Close())
			})

			conf.OpenVpn.Addr = &config.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}

			tokenStorage := tokenstorage.NewInMemory(ctx, testutils.Secret, time.Hour)
			_, openVPNClient := testutils.SetupOpenVPNOAuth2Clients(ctx, t, conf, logger.Logger, http.DefaultClient, tokenStorage)

			managementInterfaceConn, errOpenVPNClientCh, err := testutils.ConnectToManagementInterface(t, managementInterface, openVPNClient)
			require.NoError(t, err)

			reader := bufio.NewReader(managementInterfaceConn)
			testutils.ExpectVersionAndReleaseHold(t, managementInterfaceConn, reader)

			for range 12 {
				testutils.SendMessage(t, managementInterfaceConn, tc.message)
			}

			require.NoError(t, managementInterfaceConn.Close())

			select {
			case err := <-errOpenVPNClientCh:
				require.NoError(t, err)
			case <-time.After(1 * time.Second):
				t.Fatalf("timeout waiting for connection to close. Logs:\n\n%s", logger.String())
			}
		})
	}
}

func TestInvalidCommandResponses(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
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
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)

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
				require.NoError(t, managementInterface.Close())
			})

			conf.OpenVpn.Addr = &config.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}

			tokenStorage := tokenstorage.NewInMemory(ctx, testutils.Secret, time.Hour)
			_, openVPNClient := testutils.SetupOpenVPNOAuth2Clients(ctx, t, conf, logger.Logger, http.DefaultClient, tokenStorage)

			managementInterfaceConn, errOpenVPNClientCh, err := testutils.ConnectToManagementInterface(t, managementInterface, openVPNClient)
			require.NoError(t, err)

			reader := bufio.NewReader(managementInterfaceConn)

			testutils.ExpectVersionAndReleaseHold(t, managementInterfaceConn, reader)
			testutils.SendAndExpectMessage(t, managementInterfaceConn, reader,
				">HOLD:Waiting for hold release:0",
				"hold release",
			)

			testutils.SendMessage(t, managementInterfaceConn, tc.message)

			require.NoError(t, managementInterfaceConn.Close())

			select {
			case err := <-errOpenVPNClientCh:
				require.NoError(t, err)
				require.Contains(t, logger.String(), "command response not accepted")
			case <-time.After(3 * time.Second):
				t.Fatalf("timeout waiting for connection to close. Logs:\n\n%s", logger.String())
			}
		})
	}
}
