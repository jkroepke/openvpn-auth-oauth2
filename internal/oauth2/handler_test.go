package oauth2_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"text/template"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/pkg/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandler(t *testing.T) {
	t.Parallel()

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
					Secret: testutils.Secret,
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
					Secret: testutils.Secret,
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
					Secret: testutils.Secret,
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
					Secret: testutils.Secret,
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
					Secret: testutils.Secret,
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
					Secret: testutils.Secret,
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
					Secret: testutils.Secret,
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
					Secret: testutils.Secret,
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

			conf, client, managementInterface, _, httpClientListener, httpClient, shutdownFn := testutils.SetupMockEnvironment(t, tt.conf)
			defer shutdownFn()

			wg := sync.WaitGroup{}
			wg.Add(2)
			go func() {
				defer wg.Done()

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
				if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, openvpn.ErrConnectionTerminated) {
					require.NoError(t, err)
				}
			}()

			time.Sleep(time.Millisecond * 100)

			session := tt.state
			if tt.state == "-" {
				sessionState := state.New(state.ClientIdentifier{Cid: 0, Kid: 1}, tt.ipaddr, "name")
				require.NoError(t, sessionState.Encode(tt.conf.HTTP.Secret.String()))

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

			httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}

			resp, err := httpClient.Do(request)
			require.NoError(t, err)
			if tt.state != "-" {
				assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

				return
			}

			if !tt.allow {
				require.Equal(t, http.StatusForbidden, resp.StatusCode)

				return
			}

			require.Equal(t, http.StatusFound, resp.StatusCode)

			assert.NotEmpty(t, resp.Header.Get("Set-Cookie"))
			assert.Contains(t, resp.Header.Get("Set-Cookie"), "state=")
			assert.Contains(t, resp.Header.Get("Set-Cookie"), "Path=/oauth2/")
			assert.Contains(t, resp.Header.Get("Set-Cookie"), "HttpOnly")
			assert.Contains(t, resp.Header.Get("Set-Cookie"), "Max-Age=5")

			require.NotEmpty(t, resp.Header.Get("Location"))
			httpClient.CheckRedirect = nil

			request, err = http.NewRequestWithContext(context.Background(), http.MethodGet, resp.Header.Get("Location"), nil)
			require.NoError(t, err)

			resp, err = httpClient.Do(request)
			require.NoError(t, err)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			_ = resp.Body.Close()

			if conf.HTTP.CallbackTemplate != config.Defaults.HTTP.CallbackTemplate {
				require.Contains(t, string(body), "openvpn-auth-oauth2 is a management client for OpenVPN that handles the single sign-on")
			}

			assert.NotEmpty(t, resp.Header.Get("Set-Cookie"))
			assert.Contains(t, resp.Header.Get("Set-Cookie"), "state=")
			assert.Contains(t, resp.Header.Get("Set-Cookie"), "Path=/oauth2/")
			assert.Contains(t, resp.Header.Get("Set-Cookie"), "HttpOnly")
			assert.Contains(t, resp.Header.Get("Set-Cookie"), "Max-Age=0")

			client.Shutdown()
			wg.Wait()
		})
	}
}
