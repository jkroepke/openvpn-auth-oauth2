package oauth2_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
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
			"with client config and custom claim",
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
				conf.OpenVPN.ClientConfig.TokenClaim = "sub"
				conf.OpenVPN.ClientConfig.Path = types.FS{
					FS: fstest.MapFS{
						"id1.conf": &fstest.MapFile{
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
			"with client config selector + static values",
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
				conf.OpenVPN.ClientConfig.UserSelector.Enabled = true
				conf.OpenVPN.ClientConfig.UserSelector.StaticValues = []string{"static"}
				conf.OpenVPN.ClientConfig.Path = types.FS{
					FS: fstest.MapFS{
						"static.conf": &fstest.MapFile{
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
			"with client config selector + static values + not found",
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
				conf.OpenVPN.ClientConfig.UserSelector.Enabled = true
				conf.OpenVPN.ClientConfig.UserSelector.StaticValues = []string{"not found"}
				conf.OpenVPN.ClientConfig.Path = types.FS{
					FS: fstest.MapFS{
						"static.conf": &fstest.MapFile{
							Data: []byte("push \"ping 60\"\npush \"ping-restart 180\"\r\npush \"ping-timer-rem\" 0\r\n"),
						},
					},
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
			"with client config selector + multiple static values",
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
				conf.OpenVPN.ClientConfig.UserSelector.Enabled = true
				conf.OpenVPN.ClientConfig.UserSelector.StaticValues = []string{"group1", "group2"}
				conf.OpenVPN.ClientConfig.Path = types.FS{
					FS: fstest.MapFS{
						"group2.conf": &fstest.MapFile{
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

			httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			}

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

			if conf.HTTP.ShortURL {
				resp, err = httpClient.Do(request) //nolint:bodyclose
				require.NoError(t, err)

				_, err = io.Copy(io.Discard, resp.Body)
				require.NoError(t, err)

				err = resp.Body.Close()
				require.NoError(t, err)

				require.Equal(t, http.StatusFound, resp.StatusCode)
				require.NotEmpty(t, resp.Header.Get("Location"))

				request, err = http.NewRequestWithContext(t.Context(), http.MethodGet,
					httpClientListener.URL+resp.Header.Get("Location"),
					nil,
				)
				require.NoError(t, err)
			}

			if tc.xForwardedFor != "" {
				request.Header.Set("X-Forwarded-For", tc.xForwardedFor)
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

			require.Equal(t, http.StatusFound, resp.StatusCode, logger.String())
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
			case conf.OpenVPN.ClientConfig.Enabled && len(tc.conf.OpenVPN.ClientConfig.UserSelector.StaticValues) > 1:
				// Expect profile selection
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

			require.NotEmpty(t, resp.Header.Get("Set-Cookie"))
			require.Contains(t, resp.Header.Get("Set-Cookie"), "state=")
			require.Contains(t, resp.Header.Get("Set-Cookie"), "Path=/oauth2/")
			require.Contains(t, resp.Header.Get("Set-Cookie"), "HttpOnly")
			require.Contains(t, resp.Header.Get("Set-Cookie"), "Max-Age=0")

			switch {
			case len(tc.conf.OpenVPN.ClientConfig.UserSelector.StaticValues) > 1:
				require.Contains(t, string(body), "Please select your client configuration profile")

				/*
					<form method="POST" action="./profile-submit" class="profile-form">
					<input type="hidden" name="token" value="QsfAFyskl6nI6a5cQ37esh2pHX7EreJoiMKgIhv6WjJJ6xNWszk4rfpLPhyrDeQ0Y98G7mfa_rOHy58L5THkGM6Sv4Osi4iq6RWhWUxtWGpUVKlH44fjxiB_9lwMJsJ8yy6JOtaLV0wqABpgfEjtfVUyASlCQBjUO4LWtQiciC4w2UJqcOma6w3EsJLgrK8sA6g5RKnzKJq5s0F8PSS9GXmTHoRTDehh_L0vRwlP35ESBtmOwpRqlyMEFIcZgrE7SuNfRXRd4hsneTIyRrWI_-l4TodRFOkhJttMDHoyxuM1BJVlpBItLmuFYqxO_H0jtNRfixY2XEaqLmrL_F6ACzqAdpA9XLUZfDnTziRd4JhuMt_HVNeilIV5ShyLOAFR9Njw6Ceq1qSSjHMqIyvCxBdgYFVPq_eiU_ckJQFRFQNOEC02nKu_1LsWF9Tk67PkkHiAHYrYk016EJwUsOM64UqbWBRpejWRwY8Q-cDAP1TVSm1VcgDjPT8uBzePUKZS4He7f-0avvB-6XPPZHBToMIdjHZ11E0x6P5kF6UKaKdJoQVKRKXJdBHCLHCM0LcamLWgeJwKLFYrAejM4akU6xmgDQEdsPx8S7EgXUpCXSnTATG1AdxiYZZ1KTfxAPg15AOh9iNx1_ArbfCswi3exOLnoXmhKxAqMe9HSaknIPRbzrmCWi4ac4f66mKPoXUdz80jDJq135IKmXQUdrD_99gdTlh6IFgA5M6jDsEUfCJ2eQ3-rMXTY2AFmYt1rJ2STxg1nzu4hZE0qTUc8VLcGZYo5FMT-UMRiVXZhgxbxEgDMGWoyXC75JLqbLpY9kkvcvtRWeDzWN7iI0SYnuqZnehV8tUqrcSz0ZZ9zJjVqQjbzfIZc9513uAv7nrC3lGJmkHXp95HJrlVEsAly1r9Rlpl75cnqAhxB5Etktb-Yp_rMX7d99CPtobD9vDUWtPIfrE85y9Re_yh9bfTyZNtPgTacY9cJtEIfPus7ujH79Px3iwtxM5d4KcrAfc6DPsKcB3O8mAnZwkyCtd2tmdf5vGRP5b24OEfgtnNIRR-91RvwL-BLatavs1IWSF-t8717g4MinDyeVKMBUX5oWZg7_of5q-yOoSUSf-FWTlzr1_IxeDhmieLIryIx-R55t19NyV_bCpheMLGNAGs9nWadaxI-RRkzOTh6ZmswvXeHQs4FoMF0pLOmb44QciqBkQ7njkbPb0l5A==">
					<input type="hidden" name="state" value="G7dNDWp6MtCmaIpeIGhOytX-nUtbXVXTybAhzKnfWUU-6iu11lO4_lhNhy7C75NBxW2_w6PfjesPP3L6_e09KGFb">
					<input type="hidden" name="username" value="NW3N2ij9KlwdbwmpR5s3qMLlSDVf1J6Y84ymD3UR9Q==">
					<input type="hidden" name="encryptedProfiles" value="z-HJv4hlUH73YljuoVBqS7QunLUfbp1vqJw0AVSmFcGu4MzphnlzGA==">
					<input type="hidden" name="profile" value="group1">
					<button type="submit" class="profile-button">group1</button>
				*/
				reInput := regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]+)">`)

				matches := reInput.FindAllStringSubmatch(string(body), -1)
				require.NotEmpty(t, matches, "no input fields found in profile selection form")

				fields := make(map[string]string)

				for _, match := range matches {
					require.Len(t, match, 3, string(body))

					fields[match[1]] = match[2]
				}

				require.Contains(t, fields, "token")
				require.Contains(t, fields, "state")
				require.Contains(t, fields, "username")
				require.Contains(t, fields, "encryptedProfiles")
				require.Contains(t, fields, "profile")

				request, err = http.NewRequestWithContext(t.Context(), http.MethodPost,
					httpClientListener.URL+"/oauth2/profile-submit",
					strings.NewReader(fmt.Sprintf("token=%s&state=%s&username=%s&encryptedProfiles=%s&profile=%s",
						url.QueryEscape(fields["token"]),
						url.QueryEscape(fields["state"]),
						url.QueryEscape(fields["username"]),
						url.QueryEscape(fields["encryptedProfiles"]),
						url.QueryEscape(fields["profile"]),
					)),
				)

				require.NoError(t, err)

				request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

				go func() {
					var err error

					resp, err = httpClient.Do(request) //nolint:bodyclose
					reqErrCh <- err
				}()

				testutils.ExpectMessage(t, managementInterfaceConn, reader, "client-auth 0 1\r\n"+
					"push \"ping 60\"\r\n"+
					"push \"ping-restart 180\"\r\n"+
					"push \"ping-timer-rem\" 0\r\n"+
					"push \"auth-token-user bmFtZQ==\"\r\n"+
					"END")
				testutils.SendMessagef(t, managementInterfaceConn, "SUCCESS: client-auth command succeeded")

				select {
				case err := <-reqErrCh:
					require.NoError(t, err)
				case <-time.After(1 * time.Second):
					t.Fatalf("timeout waiting for request to finish. Logs:\n\n%s", logger.String())
				}

				body, err = io.ReadAll(resp.Body)
				require.NoError(t, err)

				err = resp.Body.Close()
				require.NoError(t, err)

				require.Equal(t, http.StatusOK, resp.StatusCode, logger.GetLogs())
				require.Contains(t, string(body), "Access granted")
			case conf.HTTP.Template != config.Defaults.HTTP.Template:
				require.Contains(t, string(body), "Permission is hereby granted")
			default:
				require.Contains(t, string(body), "Access granted")
			}
		})
	}
}
