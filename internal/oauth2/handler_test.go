package oauth2_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/providers/generic"
	oauth2types "github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/stretchr/testify/require"
)

func TestHandler(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name          string
		conf          config.Config
		state         state.State
		invalidState  bool
		xForwardedFor string
		preAllow      bool
		postAllow     bool
	}{
		{
			"default",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = false
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.1", "12345", ""),
			false,
			"",
			true,
			true,
		},
		{
			"with username defined",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = false
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, UsernameIsDefined: 1, CommonName: "name"}, "127.0.0.1", "12345", ""),
			false,
			"",
			true,
			true,
		},
		{
			"with acr values",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = false
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Acr = []string{"phr"}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OAuth2.Nonce = true
				conf.OAuth2.PKCE = true
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.1", "12345", ""),
			false,
			"",
			true,
			false,
		},
		{
			"with template",
			func() config.Config {
				tmpl, err := types.NewTemplate("../../LICENSE.txt")
				require.NoError(t, err)

				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = false
				conf.HTTP.Template = tmpl
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.1", "12345", ""),
			false,
			"",
			true,
			true,
		},
		{
			"with userinfo enabled",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = false
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = []string{"group1"}
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OAuth2.UserInfo = true
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.1", "12345", ""),
			false,
			"",
			true,
			true,
		},
		{
			"with userinfo enabled + validate groups",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = false
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = []string{"group0", "group1"}
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OAuth2.UserInfo = true
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.1", "12345", ""),
			false,
			"",
			true,
			true,
		},
		{
			"with userinfo enabled + missing validate groups",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = false
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = []string{"group0"}
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OAuth2.UserInfo = true
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.1", "12345", ""),
			false,
			"",
			true,
			false,
		},
		{
			"with ipaddr",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = true
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.1", "12345", ""),
			false,
			"",
			true,
			true,
		},
		{
			"with short-url",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.ShortURL = true
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.1", "12345", ""),
			false,
			"",
			true,
			true,
		},
		{
			"with ipaddr + forwarded-for",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.2", "12345", ""),
			false,
			"127.0.0.2",
			true,
			true,
		},
		{
			"with ipaddr + disabled forwarded-for",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = false
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.2", "12345", ""),
			false,
			"127.0.0.2",
			false,
			false,
		},
		{
			"with ipaddr + multiple forwarded-for",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.2", "12345", ""),
			false,
			"127.0.0.2, 8.8.8.8",
			true,
			true,
		},
		{
			"with client config found",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OpenVPN.ClientConfig.Enabled = true
				conf.OpenVPN.ClientConfig.Path = types.FS{
					FS: fstest.MapFS{
						"name.conf": &fstest.MapFile{
							Data: []byte("push \"ping 60\"\npush \"ping-restart 180\"\r\npush \"ping-timer-rem\" 0\r\n"),
						},
					},
				}

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "name"}, "127.0.0.2", "12345", ""),
			false,
			"127.0.0.2, 8.8.8.8",
			true,
			true,
		},
		{
			"with client config not found",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true
				conf.OpenVPN.ClientConfig.Enabled = true
				conf.OpenVPN.ClientConfig.Path = types.FS{
					FS: fstest.MapFS{},
				}

				return conf
			}(),
			state.New(state.ClientIdentifier{CID: 0, KID: 1, CommonName: "client"}, "127.0.0.2", "12345", ""),
			false,
			"127.0.0.2, 8.8.8.8",
			true,
			true,
		},
		{
			"with empty state",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true

				return conf
			}(),
			state.State{},
			false,
			"127.0.0.1",
			true,
			true,
		},
		{
			"with invalid state",
			func() config.Config {
				conf := config.Defaults
				conf.HTTP.Secret = testutils.Secret
				conf.HTTP.Check.IPAddr = true
				conf.HTTP.EnableProxyHeaders = true
				conf.OAuth2.Provider = generic.Name
				conf.OAuth2.Endpoints = config.OAuth2Endpoints{}
				conf.OAuth2.Scopes = []string{oauth2types.ScopeOpenID, oauth2types.ScopeProfile}
				conf.OAuth2.Validate.Groups = make([]string, 0)
				conf.OAuth2.Validate.Roles = make([]string, 0)
				conf.OAuth2.Validate.Issuer = true
				conf.OAuth2.Validate.IPAddr = false
				conf.OpenVPN.Bypass.CommonNames = make(types.RegexpSlice, 0)
				conf.OpenVPN.AuthTokenUser = true

				return conf
			}(),
			state.State{},
			true,
			"127.0.0.1",
			true,
			true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)

			conf, openVPNClient, managementInterface, _, httpClientListener, httpClient, logger := testutils.SetupMockEnvironment(ctx, t, tc.conf, nil, nil)

			managementInterfaceConn, errOpenVPNClientCh, err := testutils.ConnectToManagementInterface(t, managementInterface, openVPNClient)
			require.NoError(t, err)

			t.Cleanup(func() {
				managementInterfaceConn.Close()
				openVPNClient.Shutdown(t.Context())

				select {
				case err := <-errOpenVPNClientCh:
					require.NoError(t, err)
				case <-time.After(1 * time.Second):
					t.Fatalf("timeout waiting for connection to close. Logs:\n\n%s", logger.String())
				}
			})

			reader := bufio.NewReader(managementInterfaceConn)

			testutils.ExpectVersionAndReleaseHold(t, managementInterfaceConn, reader)

			listen, err := testutils.WaitUntilListening(t, httpClientListener.Listener.Addr().Network(), httpClientListener.Listener.Addr().String())
			if err != nil {
				return
			}

			require.NoError(t, listen.Close())

			request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, httpClientListener.URL+"/ready", nil)
			require.NoError(t, err)

			resp, err := httpClient.Do(request) //nolint:bodyclose
			require.NoError(t, err)

			require.Equal(t, http.StatusOK, resp.StatusCode)

			_, err = io.Copy(io.Discard, resp.Body)
			require.NoError(t, err)

			err = resp.Body.Close()
			require.NoError(t, err)

			var session string

			switch {
			case tc.invalidState:
				session = "invalid"
			case tc.state == (state.State{}):
				session = ""
			default:
				session, err = tc.state.Encode(conf.HTTP.Secret.String())
				require.NoError(t, err)
			}

			urlPath := "/oauth2/start?state="
			if conf.HTTP.ShortURL {
				urlPath = "/?s="
			}

			request, err = http.NewRequestWithContext(t.Context(), http.MethodGet,
				fmt.Sprintf("%s%s%s", httpClientListener.URL, urlPath, session),
				nil,
			)

			require.NoError(t, err)

			if tc.xForwardedFor != "" {
				request.Header.Set("X-Forwarded-For", tc.xForwardedFor)
			}

			httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			}

			reqErrCh := make(chan error, 1)

			go func() {
				var err error

				resp, err = httpClient.Do(request) //nolint:bodyclose
				reqErrCh <- err
			}()

			if !tc.preAllow {
				testutils.ExpectMessage(t, managementInterfaceConn, reader, `client-deny 0 1 "client rejected: http client ip 127.0.0.1 and vpn ip 127.0.0.2 is different"`)
				testutils.SendMessagef(t, managementInterfaceConn, "SUCCESS: client-deny command succeeded")
			}

			select {
			case err := <-reqErrCh:
				require.NoError(t, err)
			case <-time.After(1 * time.Second):
				t.Fatalf("timeout waiting for request to finish. Logs:\n\n%s", logger.String())
			}

			_, err = io.Copy(io.Discard, resp.Body)
			require.NoError(t, err)

			err = resp.Body.Close()
			require.NoError(t, err)

			if tc.state == (state.State{}) {
				require.Equal(t, http.StatusBadRequest, resp.StatusCode)

				return
			}

			if !tc.preAllow {
				require.Equal(t, http.StatusForbidden, resp.StatusCode)

				return
			}

			require.Equal(t, http.StatusFound, resp.StatusCode)
			require.NotEmpty(t, resp.Header.Get("Set-Cookie"))
			require.Contains(t, resp.Header.Get("Set-Cookie"), "state=")
			require.Contains(t, resp.Header.Get("Set-Cookie"), "Path=/oauth2/")
			require.Contains(t, resp.Header.Get("Set-Cookie"), "HttpOnly")
			require.Contains(t, resp.Header.Get("Set-Cookie"), "Max-Age=185")
			require.NotEmpty(t, resp.Header.Get("Location"))

			httpClient.CheckRedirect = nil

			request, err = http.NewRequestWithContext(t.Context(), http.MethodGet, resp.Header.Get("Location"), nil)
			require.NoError(t, err)

			go func() {
				var err error

				resp, err = httpClient.Do(request) //nolint:bodyclose
				reqErrCh <- err
			}()

			switch {
			case !tc.postAllow:
				testutils.ExpectMessage(t, managementInterfaceConn, reader, `client-deny 0 1 "client rejected"`)
				testutils.SendMessagef(t, managementInterfaceConn, "SUCCESS: client-deny command succeeded")
			case tc.state.Client.UsernameIsDefined == 1:
				testutils.ExpectMessage(t, managementInterfaceConn, reader, "client-auth-nt 0 1")
				testutils.SendMessagef(t, managementInterfaceConn, "SUCCESS: client-auth command succeeded")
			case conf.OpenVPN.ClientConfig.Enabled:
				if tc.state.Client.CommonName == "name" {
					testutils.ExpectMessage(t, managementInterfaceConn, reader, "client-auth 0 1\r\n"+
						"push \"ping 60\"\r\n"+
						"push \"ping-restart 180\"\r\n"+
						"push \"ping-timer-rem\" 0\r\n"+
						"push \"auth-token-user bmFtZQ==\"\r\n"+
						"END")
					testutils.SendMessagef(t, managementInterfaceConn, "SUCCESS: client-auth command succeeded")
				} else {
					testutils.ExpectMessage(t, managementInterfaceConn, reader, "client-auth 0 1\r\npush \"auth-token-user Y2xpZW50\"\r\nEND")
					testutils.SendMessagef(t, managementInterfaceConn, "SUCCESS: client-auth command succeeded")
				}
			default:
				if conf.OAuth2.UserInfo {
					testutils.ExpectMessage(t, managementInterfaceConn, reader, "client-auth 0 1\r\npush \"auth-token-user dGVzdC11c2VyQGxvY2FsaG9zdA==\"\r\nEND")
				} else {
					testutils.ExpectMessage(t, managementInterfaceConn, reader, "client-auth 0 1\r\npush \"auth-token-user bmFtZQ==\"\r\nEND")
				}

				testutils.SendMessagef(t, managementInterfaceConn, "SUCCESS: client-auth command succeeded")
			}

			select {
			case err := <-reqErrCh:
				require.NoError(t, err)
			case <-time.After(1 * time.Second):
				t.Fatalf("timeout waiting for request to finish. Logs:\n\n%s", logger.String())
			}

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			err = resp.Body.Close()
			require.NoError(t, err)

			if !tc.postAllow {
				require.Equal(t, http.StatusForbidden, resp.StatusCode, logger.GetLogs(), string(body))

				return
			}

			require.Equal(t, http.StatusOK, resp.StatusCode, logger.GetLogs(), string(body))

			if conf.HTTP.Template != config.Defaults.HTTP.Template {
				require.Contains(t, string(body), "Permission is hereby granted")
			}

			require.NotEmpty(t, resp.Header.Get("Set-Cookie"))
			require.Contains(t, resp.Header.Get("Set-Cookie"), "state=")
			require.Contains(t, resp.Header.Get("Set-Cookie"), "Path=/oauth2/")
			require.Contains(t, resp.Header.Get("Set-Cookie"), "HttpOnly")
			require.Contains(t, resp.Header.Get("Set-Cookie"), "Max-Age=0")
		})
	}
}
