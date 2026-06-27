package openvpn_test

import (
	"context"
	"errors"
	"io"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn/connection"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/test/testsuite"
	"github.com/stretchr/testify/require"
)

func TestClientInvalidServer(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	conf := config.Config{
		HTTP: config.HTTP{
			BaseURL: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
			Secret:  testsuite.Secret,
		},
		OpenVPN: config.OpenVPN{
			Addr:   types.URL{URL: &url.URL{Scheme: "tcp", Host: "127.0.0.1:1"}},
			Bypass: config.OpenVPNBypass{CommonNames: make(types.RegexpSlice, 0)},
		},
	}

	suite := testsuite.New(conf)
	_, openVPNClient := suite.SetupOpenVPNOAuth2Clients(ctx, t, nil)

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
				conf.HTTP.BaseURL = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
				conf.HTTP.Secret = testsuite.Secret
				conf.OpenVPN.CommonName.EnvironmentVariableName = config.CommonName
				conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: make(types.RegexpSlice, 0)}
				conf.OAuth2.Validate.CEL = "true"

				return conf
			}(),
			client: ">CLIENT:CONNECT,1,2\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END\r\n",
			expect: "client-pending-auth 1 2 \"WEB_AUTH::",
		},
		{
			name: "with http ip check and privacy logging disabled",
			conf: func() config.Config {
				conf := config.Defaults
				conf.HTTP.BaseURL = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
				conf.HTTP.Secret = testsuite.Secret
				conf.HTTP.Check.IPAddr = true
				conf.Log.VPNClientIP = false
				conf.OpenVPN.CommonName.EnvironmentVariableName = config.CommonName
				conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: make(types.RegexpSlice, 0)}

				return conf
			}(),
			client: ">CLIENT:CONNECT,1,2\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END\r\n",
			expect: "client-pending-auth 1 2 \"WEB_AUTH::",
		},
		{
			"with password",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.BaseURL = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
				conf.HTTP.Secret = testsuite.Secret
				conf.OpenVPN.CommonName.EnvironmentVariableName = config.CommonName
				conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: make(types.RegexpSlice, 0)}
				conf.OpenVPN.Password = testsuite.Password
				conf.OAuth2.Validate.CEL = "true"

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
				conf.HTTP.BaseURL = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
				conf.HTTP.Secret = testsuite.Secret
				conf.OpenVPN.CommonName.EnvironmentVariableName = "username"
				conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: make(types.RegexpSlice, 0)}
				conf.OAuth2.Validate.CEL = "true"

				return conf
			}(),
			client: ">CLIENT:CONNECT,1,2\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,username=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END\r\n",
			expect: "client-pending-auth 1 2 \"WEB_AUTH::",
		},
		{
			name: "with invalid state",
			conf: func() config.Config {
				conf := config.Defaults
				conf.HTTP.BaseURL = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
				conf.HTTP.Secret = "012345678910111"
				conf.OpenVPN.CommonName.EnvironmentVariableName = config.CommonName
				conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: make(types.RegexpSlice, 0)}
				conf.OpenVPN.Password = testsuite.Password

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
				conf.HTTP.BaseURL = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
				conf.HTTP.Secret = testsuite.Secret
				conf.OpenVPN.CommonName.EnvironmentVariableName = config.CommonName
				conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: make(types.RegexpSlice, 0)}
				conf.OpenVPN.Password = testsuite.Password

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
				conf.HTTP.BaseURL = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost", Path: strings.Repeat("a", 255)}}
				conf.HTTP.Secret = testsuite.Secret
				conf.OpenVPN.CommonName.EnvironmentVariableName = config.CommonName
				conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: make(types.RegexpSlice, 0)}
				conf.OpenVPN.Password = testsuite.Password

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
				conf.HTTP.BaseURL = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
				conf.HTTP.Secret = testsuite.Secret
				conf.OpenVPN.CommonName.EnvironmentVariableName = config.CommonName
				conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: types.RegexpSlice{regexp.MustCompile(`^bypass$`)}}
				conf.OpenVPN.Password = testsuite.Password
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
				conf.HTTP.BaseURL = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
				conf.HTTP.Secret = testsuite.Secret
				conf.OpenVPN.CommonName.EnvironmentVariableName = config.CommonName
				conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: types.RegexpSlice{regexp.MustCompile(`^bypass$`)}}
				conf.OpenVPN.Password = testsuite.Password
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
				conf.HTTP.BaseURL = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
				conf.HTTP.Secret = testsuite.Secret
				conf.OpenVPN.CommonName.EnvironmentVariableName = config.CommonName
				conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: types.RegexpSlice{regexp.MustCompile(`^bypass$`)}}
				conf.OpenVPN.Password = testsuite.Password

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
				conf.HTTP.BaseURL = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
				conf.HTTP.Secret = testsuite.Secret
				conf.OpenVPN.CommonName.EnvironmentVariableName = config.CommonName
				conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: types.RegexpSlice{regexp.MustCompile(`^bypass$`)}}
				conf.OpenVPN.Password = testsuite.Password

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
				conf.HTTP.BaseURL = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
				conf.HTTP.Secret = testsuite.Secret
				conf.OpenVPN.CommonName.EnvironmentVariableName = config.CommonName
				conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: types.RegexpSlice{regexp.MustCompile(`^bypass$`)}}
				conf.OpenVPN.Password = testsuite.Password

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
				conf.HTTP.BaseURL = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
				conf.HTTP.Secret = testsuite.Secret
				conf.OpenVPN.CommonName.EnvironmentVariableName = config.CommonName
				conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: types.RegexpSlice{regexp.MustCompile(`^bypass$`)}}
				conf.OpenVPN.Password = testsuite.Password

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

			suite := testsuite.New(tc.conf)
			errOpenVPNClientCh := suite.SetupManagementEnvironment(ctx, t, nil)
			t.Cleanup(func() {
				require.NoError(t, suite.GetManagementInterfaceConn().Close())

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
					t.Fatalf("timeout waiting for connection to close. Logs:\n\n%s", suite.Logs())
				}
			})

			if tc.conf.OpenVPN.Password != "" {
				suite.SendAndExpectMessage(t, "ENTER PASSWORD:", tc.conf.OpenVPN.Password.String())
				suite.SendMessagef(t, "SUCCESS: password is correct")
			}

			suite.ExpectVersionAndReleaseHold(t)
			suite.SendMessagef(t, tc.client)

			if tc.err != nil {
				_, _ = suite.GetManagementInterfaceConnReader().ReadString('\n')

				return
			} else if tc.expect == "" {
				return
			}

			auth := suite.ReadLine(t)

			if strings.Contains(tc.expect, "WEB_AUTH") {
				require.Contains(t, auth, tc.expect)
			} else {
				require.Equal(t, tc.expect, auth, suite.Logs())
			}

			if strings.Contains(tc.client, "CLIENT:ENV,password=") {
				require.Contains(t, suite.Logs(), `CLIENT:ENV,password=***`, suite.Logs())
			}

			suite.SendMessagef(t, "SUCCESS: %s command succeeded\r\n", strings.SplitN(auth, " ", 2)[0])

			if strings.Contains(auth, "client-deny") {
				suite.SendMessagef(t, ">CLIENT:DISCONNECT,0\r\n>CLIENT:ENV,END")
			} else if strings.Contains(auth, "WEB_AUTH::") {
				matches := regexp.MustCompile(`state=(.+)"`).FindStringSubmatch(auth)
				require.Len(t, matches, 2)

				sessionState, err := state.Decrypt(testsuite.Cipher, matches[1])
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

	conf := config.Defaults
	conf.OpenVPN.Password = "invalid"

	suite := testsuite.New(conf)
	errOpenVPNClientCh := suite.SetupMockEnvironment(ctx, t, nil)
	suite.SendMessagef(t, "ENTER PASSWORD:")
	suite.ExpectMessage(t, conf.OpenVPN.Password.String())
	suite.SendMessagef(t, "ERROR: bad password")

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

			suite := testsuite.New(config.Defaults)
			errOpenVPNClientCh := suite.SetupMockEnvironment(ctx, t, nil)
			suite.SendMessagef(t, openvpn.WelcomeBanner)
			suite.ExpectMessage(t, "version")
			suite.SendMessagef(t, tc.version)

			select {
			case err := <-errOpenVPNClientCh:
				require.ErrorIs(t, err, tc.err)
			case <-time.After(1 * time.Second):
				t.Fatalf("timeout waiting for connection to close. Logs:\n\n%s", suite.Logs())
			}
		})
	}
}

func TestHoldRelease(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	conf := config.Config{
		HTTP: config.HTTP{
			BaseURL: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
			Secret:  testsuite.Secret,
		},
		OpenVPN: config.OpenVPN{
			Bypass: config.OpenVPNBypass{CommonNames: make(types.RegexpSlice, 0)},
		},
	}

	suite := testsuite.New(conf)
	errOpenVPNClientCh := suite.SetupManagementEnvironment(ctx, t, nil)

	suite.ExpectVersionAndReleaseHold(t)

	for range 10 {
		suite.SendAndExpectMessage(t, ">HOLD:Waiting for hold release:0", "hold release")
	}

	require.NoError(t, suite.GetManagementInterfaceConn().Close())

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

	conf := config.Config{
		HTTP: config.HTTP{
			BaseURL: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
			Secret:  testsuite.Secret,
		},
		OpenVPN: config.OpenVPN{
			Bypass:         config.OpenVPNBypass{CommonNames: make(types.RegexpSlice, 0)},
			CommandTimeout: time.Millisecond * 300,
		},
	}

	suite := testsuite.New(conf)
	errOpenVPNClientCh := suite.SetupManagementEnvironment(ctx, t, nil)
	openVPNClient := suite.GetOpenVPNClient()

	t.Cleanup(func() {
		openVPNClient.Shutdown(t.Context())

		select {
		case err := <-errOpenVPNClientCh:
			require.NoError(t, err, suite.Logs())
		case <-time.After(1 * time.Second):
			t.Fatal("timeout waiting for connection to close")
		}
	})

	suite.ExpectVersionAndReleaseHold(t)

	defer func() {
		suite.ExpectMessage(t, "help")
		suite.SendMessagef(t, "")
	}()

	_, err := openVPNClient.SendCommandf(t.Context(), "help")
	require.ErrorIs(t, err, openvpn.ErrTimeout)
}

func TestSendCommandSerializesConcurrentCallers(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	conf := config.Config{
		HTTP: config.HTTP{
			BaseURL: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
			Secret:  testsuite.Secret,
		},
		OpenVPN: config.OpenVPN{
			Bypass:         config.OpenVPNBypass{CommonNames: make(types.RegexpSlice, 0)},
			CommandTimeout: time.Second,
		},
	}

	suite := testsuite.New(conf)
	errOpenVPNClientCh := suite.SetupManagementEnvironment(ctx, t, nil)
	openVPNClient := suite.GetOpenVPNClient()
	managementInterfaceConn := suite.GetManagementInterfaceConn()
	reader := suite.GetManagementInterfaceConnReader()

	t.Cleanup(func() {
		openVPNClient.Shutdown(t.Context())

		select {
		case err := <-errOpenVPNClientCh:
			require.NoError(t, err, suite.Logs())
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for connection to close")
		}
	})

	suite.ExpectVersionAndReleaseHold(t)

	firstErrCh := make(chan error, 1)
	secondErrCh := make(chan error, 1)

	go func() {
		_, err := openVPNClient.SendCommandf(t.Context(), "first")
		firstErrCh <- err
	}()

	suite.ExpectMessage(t, "first")

	go func() {
		_, err := openVPNClient.SendCommandf(t.Context(), "second")
		secondErrCh <- err
	}()

	require.NoError(t, managementInterfaceConn.SetReadDeadline(time.Now().Add(100*time.Millisecond)))

	_, err := reader.ReadString('\n')
	require.ErrorIs(t, err, os.ErrDeadlineExceeded)

	suite.SendMessagef(t, "SUCCESS: first command succeeded")

	select {
	case err := <-firstErrCh:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for first command")
	}

	suite.ExpectMessage(t, "second")
	suite.SendMessagef(t, "SUCCESS: second command succeeded")

	select {
	case err := <-secondErrCh:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for second command")
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

			conf := config.Defaults
			conf.HTTP.BaseURL = types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}}
			conf.HTTP.Secret = testsuite.Secret
			conf.OpenVPN.Bypass = config.OpenVPNBypass{CommonNames: make(types.RegexpSlice, 0)}

			suite := testsuite.New(conf)
			errOpenVPNClientCh := suite.SetupManagementEnvironment(ctx, t, nil)

			suite.ExpectVersionAndReleaseHold(t)

			for range 12 {
				suite.SendMessagef(t, tc.message)
			}

			require.NoError(t, suite.GetManagementInterfaceConn().Close())

			select {
			case err := <-errOpenVPNClientCh:
				require.NoError(t, err)
			case <-time.After(1 * time.Second):
				t.Fatalf("timeout waiting for connection to close. Logs:\n\n%s", suite.Logs())
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

			conf := config.Config{
				HTTP: config.HTTP{
					BaseURL: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
					Secret:  testsuite.Secret,
				},
				OpenVPN: config.OpenVPN{
					Bypass: config.OpenVPNBypass{CommonNames: make(types.RegexpSlice, 0)},
				},
			}

			suite := testsuite.New(conf)
			errOpenVPNClientCh := suite.SetupManagementEnvironment(ctx, t, nil)

			suite.ExpectVersionAndReleaseHold(t)
			suite.SendAndExpectMessage(t, ">HOLD:Waiting for hold release:0", "hold release")

			suite.SendMessagef(t, tc.message)

			require.NoError(t, suite.GetManagementInterfaceConn().Close())

			select {
			case err := <-errOpenVPNClientCh:
				require.NoError(t, err)
				require.Contains(t, suite.Logs(), "command response not accepted")
			case <-time.After(3 * time.Second):
				t.Fatalf("timeout waiting for connection to close. Logs:\n\n%s", suite.Logs())
			}
		})
	}
}
