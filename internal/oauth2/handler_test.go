package oauth2_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/storage"
	"github.com/jkroepke/openvpn-auth-oauth2/pkg/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandler(t *testing.T) {
	t.Parallel()

	logger := testutils.NewTestLogger()

	tests := []struct {
		name          string
		conf          config.Config
		ipaddr        string
		xForwardedFor string
		allow         bool
		state         string
	}{
		{
			"default",
			config.Config{
				HTTP: config.HTTP{
					Secret: testutils.HTTPSecret,
					Check: config.HTTPCheck{
						IPAddr: false,
					},
				},
				OAuth2: config.OAuth2{
					Provider:  "generic",
					Endpoints: config.OAuth2Endpoints{},
					Scopes:    []string{"openid", "profile"},
					Validate: config.OAuth2Validate{
						Groups: make([]string, 0),
						Roles:  make([]string, 0),
						Issuer: true,
						IPAddr: false,
					},
				},
				OpenVpn: config.OpenVpn{
					Bypass:        config.OpenVpnBypass{CommonNames: []string{}},
					AuthTokenUser: true,
				},
			},
			"127.0.0.1",
			"",
			true,
			"-",
		},
		{
			"with template",
			config.Config{
				HTTP: config.HTTP{
					Secret: testutils.HTTPSecret,
					Check: config.HTTPCheck{
						IPAddr: false,
					},
					CallbackTemplate: template.Must(template.New("README.md").ParseFiles("./../../README.md")),
				},
				OAuth2: config.OAuth2{
					Provider:  "generic",
					Endpoints: config.OAuth2Endpoints{},
					Scopes:    []string{"openid", "profile"},
					Validate: config.OAuth2Validate{
						Groups: make([]string, 0),
						Roles:  make([]string, 0),
						Issuer: true,
						IPAddr: false,
					},
				},
				OpenVpn: config.OpenVpn{
					Bypass:        config.OpenVpnBypass{CommonNames: []string{}},
					AuthTokenUser: true,
				},
			},
			"127.0.0.1",
			"",
			true,
			"-",
		},
		{
			"with ipaddr",
			config.Config{
				HTTP: config.HTTP{
					Secret: testutils.HTTPSecret,
					Check: config.HTTPCheck{
						IPAddr: true,
					},
				},
				OAuth2: config.OAuth2{
					Provider:  "generic",
					Endpoints: config.OAuth2Endpoints{},
					Scopes:    []string{"openid", "profile"},
					Validate: config.OAuth2Validate{
						Groups: make([]string, 0),
						Roles:  make([]string, 0),
						Issuer: true,
						IPAddr: false,
					},
				},
				OpenVpn: config.OpenVpn{
					Bypass:        config.OpenVpnBypass{CommonNames: []string{}},
					AuthTokenUser: true,
				},
			},
			"127.0.0.1",
			"",
			true,
			"-",
		},
		{
			"with ipaddr + forwarded-for",
			config.Config{
				HTTP: config.HTTP{
					Secret: testutils.HTTPSecret,
					Check: config.HTTPCheck{
						IPAddr: true,
					},
					EnableProxyHeaders: true,
				},
				OAuth2: config.OAuth2{
					Provider:  "generic",
					Endpoints: config.OAuth2Endpoints{},
					Scopes:    []string{"openid", "profile"},
					Validate: config.OAuth2Validate{
						Groups: make([]string, 0),
						Roles:  make([]string, 0),
						Issuer: true,
						IPAddr: false,
					},
				},
				OpenVpn: config.OpenVpn{
					Bypass:        config.OpenVpnBypass{CommonNames: []string{}},
					AuthTokenUser: true,
				},
			},
			"127.0.0.2",
			"127.0.0.2",
			true,
			"-",
		},
		{
			"with ipaddr + disabled forwarded-for",
			config.Config{
				HTTP: config.HTTP{
					Secret: testutils.HTTPSecret,
					Check: config.HTTPCheck{
						IPAddr: true,
					},
					EnableProxyHeaders: false,
				},
				OAuth2: config.OAuth2{
					Provider:  "generic",
					Endpoints: config.OAuth2Endpoints{},
					Scopes:    []string{"openid", "profile"},
					Validate: config.OAuth2Validate{
						Groups: make([]string, 0),
						Roles:  make([]string, 0),
						Issuer: true,
						IPAddr: false,
					},
				},
				OpenVpn: config.OpenVpn{
					Bypass:        config.OpenVpnBypass{CommonNames: []string{}},
					AuthTokenUser: true,
				},
			},
			"127.0.0.2",
			"127.0.0.2",
			false,
			"-",
		},
		{
			"with ipaddr + multiple forwarded-for",
			config.Config{
				HTTP: config.HTTP{
					Secret: testutils.HTTPSecret,
					Check: config.HTTPCheck{
						IPAddr: true,
					},
					EnableProxyHeaders: true,
				},
				OAuth2: config.OAuth2{
					Provider:  "generic",
					Endpoints: config.OAuth2Endpoints{},
					Scopes:    []string{"openid", "profile"},
					Validate: config.OAuth2Validate{
						Groups: make([]string, 0),
						Roles:  make([]string, 0),
						Issuer: true,
						IPAddr: false,
					},
				},
				OpenVpn: config.OpenVpn{
					Bypass:        config.OpenVpnBypass{CommonNames: []string{}},
					AuthTokenUser: true,
				},
			},
			"127.0.0.2",
			"127.0.0.2, 8.8.8.8",
			true,
			"-",
		},
		{
			"with empty state",
			config.Config{
				HTTP: config.HTTP{
					Secret: testutils.HTTPSecret,
					Check: config.HTTPCheck{
						IPAddr: true,
					},
					EnableProxyHeaders: true,
				},
				OAuth2: config.OAuth2{
					Provider:  "generic",
					Endpoints: config.OAuth2Endpoints{},
					Scopes:    []string{"openid", "profile"},
					Validate: config.OAuth2Validate{
						Groups: make([]string, 0),
						Roles:  make([]string, 0),
						Issuer: true,
						IPAddr: false,
					},
				},
				OpenVpn: config.OpenVpn{
					Bypass:        config.OpenVpnBypass{CommonNames: []string{}},
					AuthTokenUser: true,
				},
			},
			"127.0.0.1",
			"127.0.0.1",
			true,
			"",
		},
		{
			"with invalid state",
			config.Config{
				HTTP: config.HTTP{
					Secret: testutils.HTTPSecret,
					Check: config.HTTPCheck{
						IPAddr: true,
					},
					EnableProxyHeaders: true,
				},
				OAuth2: config.OAuth2{
					Provider:  "generic",
					Endpoints: config.OAuth2Endpoints{},
					Scopes:    []string{"openid", "profile"},
					Validate: config.OAuth2Validate{
						Groups: make([]string, 0),
						Roles:  make([]string, 0),
						Issuer: true,
						IPAddr: false,
					},
				},
				OpenVpn: config.OpenVpn{
					Bypass:        config.OpenVpnBypass{CommonNames: []string{}},
					AuthTokenUser: true,
				},
			},
			"127.0.0.1",
			"127.0.0.1",
			true,
			"test",
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			managementInterface, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer managementInterface.Close()

			clientListener, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			defer clientListener.Close()

			resourceServer, clientCredentials, err := testutils.SetupResourceServer(clientListener)
			require.NoError(t, err)
			defer resourceServer.Close()

			resourceServerURL, err := url.Parse(resourceServer.URL)
			require.NoError(t, err)

			tt.conf.OAuth2.Client = clientCredentials
			tt.conf.OAuth2.Issuer = resourceServerURL
			tt.conf.HTTP.BaseURL = &url.URL{Scheme: "http", Host: clientListener.Addr().String()}
			tt.conf.OpenVpn.Addr = &url.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}
			if tt.conf.HTTP.CallbackTemplate == nil {
				tt.conf.HTTP.CallbackTemplate = config.Defaults.HTTP.CallbackTemplate
			}

			storageClient := storage.New(time.Hour)

			provider := oauth2.New(logger, tt.conf, storageClient)

			client := openvpn.NewClient(logger, tt.conf, provider)
			defer client.Shutdown()

			err = provider.Discover(client)
			require.NoError(t, err)

			httpClientListener := httptest.NewUnstartedServer(provider.Handler())
			httpClientListener.Listener.Close()
			httpClientListener.Listener = clientListener
			httpClientListener.Start()
			defer httpClientListener.Close()

			httpClient := httpClientListener.Client()

			wg := sync.WaitGroup{}
			wg.Add(2)
			go func() {
				defer wg.Done()
				defer client.Shutdown()

				conn, err := managementInterface.Accept()
				require.NoError(t, err)

				defer conn.Close()
				reader := bufio.NewReader(conn)

				testutils.SendLine(t, conn, ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\r\n")
				assert.Equal(t, "hold release", testutils.ReadLine(t, reader))
				testutils.SendLine(t, conn, "SUCCESS: hold release succeeded\r\n")
				assert.Equal(t, "version", testutils.ReadLine(t, reader))

				testutils.SendLine(t, conn, "OpenVPN Version: OpenVPN Mock\r\nManagement Interface Version: 5\r\nEND\r\n")
				if tt.state != "-" {
					return
				}

				if tt.allow {
					assert.Equal(t, "client-auth 0 1", testutils.ReadLine(t, reader))
					assert.Equal(t, "push \"auth-token-user aWQx\"", testutils.ReadLine(t, reader))
					assert.Equal(t, "END", testutils.ReadLine(t, reader))
				} else {
					assert.Equal(t, `client-deny 0 1 "http client ip 127.0.0.1 and vpn ip 127.0.0.2 is different."`, testutils.ReadLine(t, reader))
				}

				testutils.SendLine(t, conn, "SUCCESS: client-auth command succeeded\r\n")
			}()

			go func() {
				defer wg.Done()
				err := client.Connect()
				if err != nil && !strings.HasSuffix(err.Error(), "EOF") {
					require.NoError(t, err)
				}
			}()

			jar, err := cookiejar.New(nil)
			require.NoError(t, err)

			httpClient.Jar = jar

			time.Sleep(time.Millisecond * 100)

			session := tt.state
			if tt.state == "-" {
				sessionState := state.New(state.ClientIdentifier{Cid: 0, Kid: 1}, tt.ipaddr, "name")
				err = sessionState.Encode(tt.conf.HTTP.Secret.String())
				require.NoError(t, err)

				session = sessionState.Encoded()
			}

			request, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
				fmt.Sprintf("%s/oauth2/start?state=%s", httpClientListener.URL, session),
				nil,
			)

			require.NoError(t, err)

			if tt.xForwardedFor != "" {
				request.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}

			resp, err := httpClient.Do(request)
			require.NoError(t, err)

			if tt.state != "-" {
				assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

				return
			}

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			_ = resp.Body.Close()

			expectedStatus := 200
			if !tt.allow {
				expectedStatus = 403
			}

			if !assert.Equal(t, expectedStatus, resp.StatusCode, string(body)) {
				return
			}

			if tt.conf.HTTP.CallbackTemplate != config.Defaults.HTTP.CallbackTemplate {
				if !assert.Contains(t, string(body), "openvpn-auth-oauth2 is a management client for OpenVPN that handles the single sign-on") {
					return
				}
			}

			client.Shutdown()
			wg.Wait()
		})
	}
}
