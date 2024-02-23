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
		preAllow      bool
		postAllow     bool
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
			true,
			"-",
		},
		{
			"with acr values",
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
						Acr:    []string{"phr"},
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
			false,
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
					CallbackTemplate: template.Must(template.New("LICENSE.txt").ParseFiles("./../../LICENSE.txt")),
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
			true,
			"test",
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			conf, client, managementInterface, _, httpClientListener, httpClient, logger, shutdownFn := testutils.SetupMockEnvironment(t, tt.conf)
			defer shutdownFn()

			wg := sync.WaitGroup{}
			wg.Add(2)

			go func() {
				defer wg.Done()

				managementInterfaceConn, err := managementInterface.Accept()
				require.NoError(t, err) //nolint:testifylint

				defer managementInterfaceConn.Close()
				reader := bufio.NewReader(managementInterfaceConn)

				testutils.ExpectVersionAndReleaseHold(t, managementInterfaceConn, reader)

				if tt.state != "-" {
					return
				}

				switch {
				case !tt.preAllow:
					testutils.ExpectMessage(t, managementInterfaceConn, reader, `client-deny 0 1 "http client ip 127.0.0.1 and vpn ip 127.0.0.2 is different."`)
				case !tt.postAllow:
					testutils.ExpectMessage(t, managementInterfaceConn, reader, `client-deny 0 1 "client rejected"`)
				default:
					testutils.ExpectMessage(t, managementInterfaceConn, reader, "client-auth 0 1\npush \"auth-token-user aWQx\"\nEND")
				}

				testutils.SendMessage(t, managementInterfaceConn, "SUCCESS: client-auth command succeeded")
			}()

			go func() {
				defer wg.Done()

				err := client.Connect()

				if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, openvpn.ErrConnectionTerminated) {
					require.NoError(t, err) //nolint:testifylint
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

			httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			}

			resp, err := httpClient.Do(request)
			require.NoError(t, err)

			_, err = io.Copy(io.Discard, resp.Body)
			require.NoError(t, err)
			resp.Body.Close()

			if tt.state != "-" {
				assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

				return
			}

			if !tt.preAllow {
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

			if !tt.postAllow {
				require.Equal(t, http.StatusForbidden, resp.StatusCode, logger.GetLogs(), string(body))

				return
			}

			require.Equal(t, http.StatusOK, resp.StatusCode, logger.GetLogs(), string(body))

			_ = resp.Body.Close()

			if conf.HTTP.CallbackTemplate != config.Defaults.HTTP.CallbackTemplate {
				require.Contains(t, string(body), "Permission is hereby granted")
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
