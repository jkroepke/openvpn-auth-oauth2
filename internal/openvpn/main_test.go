package openvpn_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
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
			BaseURL: &url.URL{Scheme: "http", Host: "localhost"},
			Secret:  testutils.Secret,
		},
		OpenVPN: config.OpenVPN{
			Addr:   &url.URL{Scheme: "tcp", Host: "127.0.0.1:1"},
			Bypass: config.OpenVPNBypass{CommonNames: make([]*regexp.Regexp, 0)},
		},
	}

	tokenStorage := tokenstorage.NewInMemory(testutils.Secret, time.Hour)
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
			conf: func() config.Config {
				conf := config.Defaults
				conf.HTTP.BaseURL = &url.URL{Scheme: "http", Host: "localhost"}
				conf.HTTP.Secret = testutils.Secret
				conf.OpenVPN.CommonName.EnvironmentVariableName = config.CommonName
				conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: make([]*regexp.Regexp, 0)}
				conf.OAuth2.Validate.IPAddr = true

				return conf
			}(),
			client: ">CLIENT:CONNECT,1,2\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END\r\n",
			expect: "client-pending-auth 1 2 \"WEB_AUTH::",
		},
		{
			"with password",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.BaseURL = &url.URL{Scheme: "http", Host: "localhost"}
				conf.HTTP.Secret = testutils.Secret
				conf.OpenVPN.CommonName.EnvironmentVariableName = config.CommonName
				conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: make([]*regexp.Regexp, 0)}
				conf.OpenVPN.Password = testutils.Password
				conf.OAuth2.Validate.IPAddr = true

				return conf
			}(),
			">CLIENT:CONNECT,1,2\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END\r\n",
			"client-pending-auth 1 2 \"WEB_AUTH::",
			nil,
		},
		{
			name: "with username",
			conf: func() config.Config {
				conf := config.Defaults
				conf.HTTP.BaseURL = &url.URL{Scheme: "http", Host: "localhost"}
				conf.HTTP.Secret = testutils.Secret
				conf.OpenVPN.CommonName.EnvironmentVariableName = "username"
				conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: make([]*regexp.Regexp, 0)}
				conf.OAuth2.Validate.IPAddr = true

				return conf
			}(),
			client: ">CLIENT:CONNECT,1,2\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,username=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END\r\n",
			expect: "client-pending-auth 1 2 \"WEB_AUTH::",
		},
		{
			name: "with invalid state",
			conf: func() config.Config {
				conf := config.Defaults
				conf.HTTP.BaseURL = &url.URL{Scheme: "http", Host: "localhost"}
				conf.HTTP.Secret = "012345678910111"
				conf.OpenVPN.CommonName.EnvironmentVariableName = config.CommonName
				conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: make([]*regexp.Regexp, 0)}
				conf.OpenVPN.Password = testutils.Password

				return conf
			}(),
			client: ">CLIENT:CONNECT,1,2\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END\r\n",
			expect: "",
			err:    nil,
		},
		{
			name: "client without IV_SSO",
			conf: func() config.Config {
				conf := config.Defaults
				conf.HTTP.BaseURL = &url.URL{Scheme: "http", Host: "localhost"}
				conf.HTTP.Secret = testutils.Secret
				conf.OpenVPN.CommonName.EnvironmentVariableName = config.CommonName
				conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: make([]*regexp.Regexp, 0)}
				conf.OpenVPN.Password = testutils.Password

				return conf
			}(),
			client: ">CLIENT:CONNECT,0,1\r\n>CLIENT:ENV,daemon=0\r\n>CLIENT:ENV,END\r\n",
			expect: "client-deny 0 1 \"OpenVPN Client does not support SSO authentication via webauth\"",
			err:    nil,
		},
		{
			"to long base url",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.BaseURL = &url.URL{Scheme: "http", Host: "localhost", Path: strings.Repeat("a", 255)}
				conf.HTTP.Secret = testutils.Secret
				conf.OpenVPN.CommonName.EnvironmentVariableName = config.CommonName
				conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: make([]*regexp.Regexp, 0)}
				conf.OpenVPN.Password = testutils.Password

				return conf
			}(),
			">CLIENT:CONNECT,1,2\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END\r\n",
			`client-deny 1 2 "internal error"`,
			nil,
		},
		{
			"client bypass",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.BaseURL = &url.URL{Scheme: "http", Host: "localhost"}
				conf.HTTP.Secret = testutils.Secret
				conf.OpenVPN.CommonName.EnvironmentVariableName = config.CommonName
				conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: []*regexp.Regexp{regexp.MustCompile(`^bypass$`)}}
				conf.OpenVPN.Password = testutils.Password
				conf.OpenVPN.AuthTokenUser = false

				return conf
			}(),
			">CLIENT:CONNECT,0,1\r\n>CLIENT:ENV,common_name=bypass\r\n>CLIENT:ENV,END\r\n",
			"client-auth-nt 0 1",
			nil,
		},
		{
			name: "client password mask",
			conf: func() config.Config {
				conf := config.Defaults
				conf.HTTP.BaseURL = &url.URL{Scheme: "http", Host: "localhost"}
				conf.HTTP.Secret = testutils.Secret
				conf.OpenVPN.CommonName.EnvironmentVariableName = config.CommonName
				conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: []*regexp.Regexp{regexp.MustCompile(`^bypass$`)}}
				conf.OpenVPN.Password = testutils.Password
				conf.OpenVPN.AuthTokenUser = false

				return conf
			}(),
			client: ">CLIENT:CONNECT,0,1\r\n>CLIENT:ENV,common_name=bypass\r\nCLIENT:ENV,password=important value\n>CLIENT:ENV,END\r\n",
			expect: "client-auth-nt 0 1",
		},
		{
			"client established",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.BaseURL = &url.URL{Scheme: "http", Host: "localhost"}
				conf.HTTP.Secret = testutils.Secret
				conf.OpenVPN.CommonName.EnvironmentVariableName = config.CommonName
				conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: []*regexp.Regexp{regexp.MustCompile(`^bypass$`)}}
				conf.OpenVPN.Password = testutils.Password

				return conf
			}(),
			">CLIENT:ESTABLISHED,0\r\n>CLIENT:ENV,common_name=bypass\r\n>CLIENT:ENV,END\r\n",
			"",
			nil,
		},
		{
			"client disconnected",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.BaseURL = &url.URL{Scheme: "http", Host: "localhost"}
				conf.HTTP.Secret = testutils.Secret
				conf.OpenVPN.CommonName.EnvironmentVariableName = config.CommonName
				conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: []*regexp.Regexp{regexp.MustCompile(`^bypass$`)}}
				conf.OpenVPN.Password = testutils.Password

				return conf
			}(),
			">CLIENT:DISCONNECT,0\r\n>CLIENT:ENV,common_name=bypass\r\n>CLIENT:ENV,END\r\n",
			"",
			nil,
		},
		{
			"client invalid reason 1",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.BaseURL = &url.URL{Scheme: "http", Host: "localhost"}
				conf.HTTP.Secret = testutils.Secret
				conf.OpenVPN.CommonName.EnvironmentVariableName = config.CommonName
				conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: []*regexp.Regexp{regexp.MustCompile(`^bypass$`)}}
				conf.OpenVPN.Password = testutils.Password

				return conf
			}(),
			">CLIENT:FOO,0\r\n>CLIENT:ENV,common_name=bypass\r\n>CLIENT:ENV,END\r\n",
			"",
			connection.ErrParseErrorClientReason,
		},
		{
			"client invalid reason 2",

			func() config.Config {
				conf := config.Defaults
				conf.HTTP.BaseURL = &url.URL{Scheme: "http", Host: "localhost"}
				conf.HTTP.Secret = testutils.Secret
				conf.OpenVPN.CommonName.EnvironmentVariableName = config.CommonName
				conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: []*regexp.Regexp{regexp.MustCompile(`^bypass$`)}}
				conf.OpenVPN.Password = testutils.Password

				return conf
			}(),
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

			tc.conf.OpenVPN.Addr = &url.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}

			tokenStorage := tokenstorage.NewInMemory(testutils.Secret, time.Hour)
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

			if tc.conf.OpenVPN.Password != "" {
				testutils.SendAndExpectMessage(t, managementInterfaceConn, reader, "ENTER PASSWORD:", tc.conf.OpenVPN.Password.String())
				testutils.SendMessagef(t, managementInterfaceConn, "SUCCESS: password is correct")
			}

			testutils.ExpectVersionAndReleaseHold(t, managementInterfaceConn, reader)
			testutils.SendMessagef(t, managementInterfaceConn, tc.client)

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

			testutils.SendMessagef(t, managementInterfaceConn, "SUCCESS: %s command succeeded\r\n", strings.SplitN(auth, " ", 2)[0])

			if strings.Contains(auth, "client-deny") {
				testutils.SendMessagef(t, managementInterfaceConn, ">CLIENT:DISCONNECT,0\r\n>CLIENT:ENV,END")
			} else if strings.Contains(auth, "WEB_AUTH::") {
				matches := regexp.MustCompile(`state=(.+)"`).FindStringSubmatch(auth)
				require.Len(t, matches, 2)

				sessionState, err := state.NewWithEncodedToken(matches[1], tc.conf.HTTP.Secret.String())
				require.NoError(t, err)

				require.Equal(t, uint64(1), sessionState.Client.CID)
				require.Equal(t, uint64(2), sessionState.Client.KID)
				require.Equal(t, "test", sessionState.Client.CommonName)
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
			BaseURL: &url.URL{Scheme: "http", Host: "localhost"},
			Secret:  testutils.Secret,
		},
		OpenVPN: config.OpenVPN{
			Addr:     &url.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()},
			Bypass:   config.OpenVPNBypass{CommonNames: make([]*regexp.Regexp, 0)},
			Password: "invalid",
		},
	}

	tokenStorage := tokenstorage.NewInMemory(testutils.Secret, time.Hour)
	_, openVPNClient := testutils.SetupOpenVPNOAuth2Clients(ctx, t, conf, logger.Logger, http.DefaultClient, tokenStorage)

	managementInterfaceConn, errOpenVPNClientCh, err := testutils.ConnectToManagementInterface(t, managementInterface, openVPNClient)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, managementInterfaceConn.Close())
	})

	reader := bufio.NewReader(managementInterfaceConn)

	testutils.SendMessagef(t, managementInterfaceConn, "ENTER PASSWORD:")
	testutils.ExpectMessage(t, managementInterfaceConn, reader, conf.OpenVPN.Password.String())
	testutils.SendMessagef(t, managementInterfaceConn, "ERROR: bad password")

	select {
	case err := <-errOpenVPNClientCh:
		require.ErrorIs(t, err, openvpn.ErrInvalidPassword)
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for connection to close")
	}
}

func TestClientInvalidVersion(t *testing.T) {
	t.Parallel()

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

			managementInterface, err := nettest.NewLocalListener("tcp")
			require.NoError(t, err)

			t.Cleanup(func() {
				require.NoError(t, managementInterface.Close())
			})

			conf := config.Defaults
			conf.HTTP.BaseURL = &url.URL{Scheme: "http", Host: "localhost"}
			conf.HTTP.Secret = testutils.Secret
			conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: []*regexp.Regexp{regexp.MustCompile(`^bypass$`)}}
			conf.OpenVPN.Addr = &url.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}

			tokenStorage := tokenstorage.NewInMemory(testutils.Secret, time.Hour)
			_, openVPNClient := testutils.SetupOpenVPNOAuth2Clients(ctx, t, conf, logger.Logger, http.DefaultClient, tokenStorage)

			managementInterfaceConn, errOpenVPNClientCh, err := testutils.ConnectToManagementInterface(t, managementInterface, openVPNClient)
			require.NoError(t, err)

			reader := bufio.NewReader(managementInterfaceConn)

			testutils.SendAndExpectMessage(t, managementInterfaceConn, reader,
				openvpn.WelcomeBanner,
				"version",
			)

			testutils.SendMessagef(t, managementInterfaceConn, tc.version)

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
			BaseURL: &url.URL{Scheme: "http", Host: "localhost"},
			Secret:  testutils.Secret,
		},
		OpenVPN: config.OpenVPN{
			Bypass: config.OpenVPNBypass{CommonNames: make([]*regexp.Regexp, 0)},
		},
	}

	managementInterface, err := nettest.NewLocalListener("tcp")
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, managementInterface.Close())
	})

	conf.OpenVPN.Addr = &url.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}

	tokenStorage := tokenstorage.NewInMemory(testutils.Secret, time.Hour)
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

func TestCommandTimeout(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	logger := testutils.NewTestLogger()

	conf := config.Config{
		HTTP: config.HTTP{
			BaseURL: &url.URL{Scheme: "http", Host: "localhost"},
			Secret:  testutils.Secret,
		},
		OpenVPN: config.OpenVPN{
			Bypass:         config.OpenVPNBypass{CommonNames: make([]*regexp.Regexp, 0)},
			CommandTimeout: time.Millisecond * 300,
		},
	}

	managementInterface, err := nettest.NewLocalListener("tcp")
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, managementInterface.Close())
	})

	conf.OpenVPN.Addr = &url.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}

	tokenStorage := tokenstorage.NewInMemory(testutils.Secret, time.Hour)
	_, openVPNClient := testutils.SetupOpenVPNOAuth2Clients(ctx, t, conf, logger.Logger, http.DefaultClient, tokenStorage)

	managementInterfaceConn, errOpenVPNClientCh, err := testutils.ConnectToManagementInterface(t, managementInterface, openVPNClient)
	require.NoError(t, err)

	t.Cleanup(func() {
		openVPNClient.Shutdown(t.Context())

		select {
		case err := <-errOpenVPNClientCh:
			require.NoError(t, err, logger.String())
		case <-time.After(1 * time.Second):
			t.Fatal("timeout waiting for connection to close")
		}
	})

	reader := bufio.NewReader(managementInterfaceConn)

	testutils.ExpectVersionAndReleaseHold(t, managementInterfaceConn, reader)

	defer func() {
		testutils.ExpectMessage(t, managementInterfaceConn, reader, "help")
		testutils.SendMessagef(t, managementInterfaceConn, "")
	}()

	_, err = openVPNClient.SendCommandf(t.Context(), "help")
	require.ErrorIs(t, err, openvpn.ErrTimeout)
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

			conf := config.Defaults
			conf.HTTP.BaseURL = &url.URL{Scheme: "http", Host: "localhost"}
			conf.HTTP.Secret = testutils.Secret
			conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: make([]*regexp.Regexp, 0)}

			managementInterface, err := nettest.NewLocalListener("tcp")
			require.NoError(t, err)

			t.Cleanup(func() {
				require.NoError(t, managementInterface.Close())
			})

			conf.OpenVPN.Addr = &url.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}

			tokenStorage := tokenstorage.NewInMemory(testutils.Secret, time.Hour)
			_, openVPNClient := testutils.SetupOpenVPNOAuth2Clients(ctx, t, conf, logger.Logger, http.DefaultClient, tokenStorage)

			managementInterfaceConn, errOpenVPNClientCh, err := testutils.ConnectToManagementInterface(t, managementInterface, openVPNClient)
			require.NoError(t, err)

			reader := bufio.NewReader(managementInterfaceConn)
			testutils.ExpectVersionAndReleaseHold(t, managementInterfaceConn, reader)

			for range 12 {
				testutils.SendMessagef(t, managementInterfaceConn, tc.message)
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
					BaseURL: &url.URL{Scheme: "http", Host: "localhost"},
					Secret:  testutils.Secret,
				},
				OpenVPN: config.OpenVPN{
					Bypass: config.OpenVPNBypass{CommonNames: make([]*regexp.Regexp, 0)},
				},
			}

			managementInterface, err := nettest.NewLocalListener("tcp")
			require.NoError(t, err)

			t.Cleanup(func() {
				require.NoError(t, managementInterface.Close())
			})

			conf.OpenVPN.Addr = &url.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}

			tokenStorage := tokenstorage.NewInMemory(testutils.Secret, time.Hour)
			_, openVPNClient := testutils.SetupOpenVPNOAuth2Clients(ctx, t, conf, logger.Logger, http.DefaultClient, tokenStorage)

			managementInterfaceConn, errOpenVPNClientCh, err := testutils.ConnectToManagementInterface(t, managementInterface, openVPNClient)
			require.NoError(t, err)

			reader := bufio.NewReader(managementInterfaceConn)

			testutils.ExpectVersionAndReleaseHold(t, managementInterfaceConn, reader)
			testutils.SendAndExpectMessage(t, managementInterfaceConn, reader,
				">HOLD:Waiting for hold release:0",
				"hold release",
			)

			testutils.SendMessagef(t, managementInterfaceConn, tc.message)

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
