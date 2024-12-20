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
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/stretchr/testify/assert"
)

func TestHandler(t *testing.T) {
	t.Parallel()

	tests := []struct {
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
					Bypass:        config.OpenVpnBypass{CommonNames: make([]string, 0)},
					AuthTokenUser: true,
				},
			},
			state.New(state.ClientIdentifier{CID: 0, KID: 1}, "127.0.0.1", "12345", "name", ""),
			false,
			"",
			true,
			true,
		},
		{
			"with username defined",
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
					Bypass:        config.OpenVpnBypass{CommonNames: make([]string, 0)},
					AuthTokenUser: true,
				},
			},
			state.New(state.ClientIdentifier{CID: 0, KID: 1, UsernameIsDefined: 1}, "127.0.0.1", "12345", "name", ""),
			false,
			"",
			true,
			true,
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
					Nonce: true,
					PKCE:  true,
				},
				OpenVpn: config.OpenVpn{
					Bypass:        config.OpenVpnBypass{CommonNames: make([]string, 0)},
					AuthTokenUser: true,
				},
			},
			state.New(state.ClientIdentifier{CID: 0, KID: 1}, "127.0.0.1", "12345", "name", ""),
			false,
			"",
			true,
			false,
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
					Bypass:        config.OpenVpnBypass{CommonNames: make([]string, 0)},
					AuthTokenUser: true,
				},
			},
			state.New(state.ClientIdentifier{CID: 0, KID: 1}, "127.0.0.1", "12345", "name", ""),
			false,
			"",
			true,
			true,
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
					Bypass:        config.OpenVpnBypass{CommonNames: make([]string, 0)},
					AuthTokenUser: true,
				},
			},
			state.New(state.ClientIdentifier{CID: 0, KID: 1}, "127.0.0.1", "12345", "name", ""),
			false,
			"",
			true,
			true,
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
					Bypass:        config.OpenVpnBypass{CommonNames: make([]string, 0)},
					AuthTokenUser: true,
				},
			},
			state.New(state.ClientIdentifier{CID: 0, KID: 1}, "127.0.0.2", "12345", "name", ""),
			false,
			"127.0.0.2",
			true,
			true,
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
					Bypass:        config.OpenVpnBypass{CommonNames: make([]string, 0)},
					AuthTokenUser: true,
				},
			},
			state.New(state.ClientIdentifier{CID: 0, KID: 1}, "127.0.0.2", "12345", "name", ""),
			false,
			"127.0.0.2",
			false,
			false,
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
					Bypass:        config.OpenVpnBypass{CommonNames: make([]string, 0)},
					AuthTokenUser: true,
				},
			},
			state.New(state.ClientIdentifier{CID: 0, KID: 1}, "127.0.0.2", "12345", "name", ""),
			false,
			"127.0.0.2, 8.8.8.8",
			true,
			true,
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
					Bypass:        config.OpenVpnBypass{CommonNames: make([]string, 0)},
					AuthTokenUser: true,
				},
			},
			state.State{},
			false,
			"127.0.0.1",
			true,
			true,
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
					Bypass:        config.OpenVpnBypass{CommonNames: make([]string, 0)},
					AuthTokenUser: true,
				},
			},
			state.State{},
			true,
			"127.0.0.1",
			true,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithCancel(context.Background())

			conf, client, managementInterface, _, httpClientListener, httpClient, logger, shutdownFn := testutils.SetupMockEnvironment(ctx, t, tt.conf, nil)
			defer shutdownFn()

			wg := sync.WaitGroup{}
			wg.Add(3)

			go func() {
				defer wg.Done()

				managementInterfaceConn, err := managementInterface.Accept()
				if err != nil {
					assert.NoError(t, fmt.Errorf("accepting connection: %w", err))
					cancel()

					return
				}

				defer managementInterfaceConn.Close()
				reader := bufio.NewReader(managementInterfaceConn)

				testutils.ExpectVersionAndReleaseHold(t, managementInterfaceConn, reader)

				if tt.state == (state.State{}) {
					return
				}

				switch {
				case !tt.preAllow:
					testutils.ExpectMessage(t, managementInterfaceConn, reader, `client-deny 0 1 "http client ip 127.0.0.1 and vpn ip 127.0.0.2 is different."`)
				case !tt.postAllow:
					testutils.ExpectMessage(t, managementInterfaceConn, reader, `client-deny 0 1 "client rejected"`)
				case tt.state.Client.UsernameIsDefined == 1:
					testutils.ExpectMessage(t, managementInterfaceConn, reader, "client-auth-nt 0 1")
				default:
					testutils.ExpectMessage(t, managementInterfaceConn, reader, "client-auth 0 1\r\npush \"auth-token-user bmFtZQ==\"\r\nEND")
				}

				testutils.SendMessage(t, managementInterfaceConn, "SUCCESS: client-auth command succeeded")
			}()

			go func() {
				defer wg.Done()

				err := client.Connect()

				if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, openvpn.ErrConnectionTerminated) {
					assert.NoError(t, err)
					cancel()

					return
				}
			}()

			go func() {
				defer wg.Done()
				defer cancel()

				time.Sleep(time.Millisecond * 100)

				var (
					session string
					err     error
				)

				request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, httpClientListener.URL+"/ready", nil)
				if !assert.NoError(t, err) {
					return
				}

				resp, err := httpClient.Do(request)
				if !assert.NoError(t, err) {
					return
				}

				_, err = io.Copy(io.Discard, resp.Body)
				if !assert.NoError(t, err) {
					return
				}

				resp.Body.Close()

				if !assert.Equal(t, http.StatusOK, resp.StatusCode) {
					return
				}

				switch {
				case tt.invalidState:
					session = "invalid"
				case tt.state == (state.State{}):
					session = ""
				default:
					session, err = tt.state.Encode(tt.conf.HTTP.Secret.String())
					if !assert.NoError(t, err) {
						return
					}
				}

				request, err = http.NewRequestWithContext(context.Background(), http.MethodGet,
					fmt.Sprintf("%s/oauth2/start?state=%s", httpClientListener.URL, session),
					nil,
				)

				if !assert.NoError(t, err) {
					return
				}

				if tt.xForwardedFor != "" {
					request.Header.Set("X-Forwarded-For", tt.xForwardedFor)
				}

				httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
					return http.ErrUseLastResponse
				}

				resp, err = httpClient.Do(request)
				if !assert.NoError(t, err) {
					return
				}

				_, err = io.Copy(io.Discard, resp.Body)
				if !assert.NoError(t, err) {
					return
				}

				resp.Body.Close()

				if tt.state == (state.State{}) {
					assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

					return
				}

				if !tt.preAllow {
					assert.Equal(t, http.StatusForbidden, resp.StatusCode)

					return
				}

				if !assert.Equal(t, http.StatusFound, resp.StatusCode) {
					return
				}

				assert.NotEmpty(t, resp.Header.Get("Set-Cookie"))
				assert.Contains(t, resp.Header.Get("Set-Cookie"), "state=")
				assert.Contains(t, resp.Header.Get("Set-Cookie"), "Path=/oauth2/")
				assert.Contains(t, resp.Header.Get("Set-Cookie"), "HttpOnly")
				assert.Contains(t, resp.Header.Get("Set-Cookie"), "Max-Age=5")

				if !assert.NotEmpty(t, resp.Header.Get("Location")) {
					return
				}

				httpClient.CheckRedirect = nil

				request, err = http.NewRequestWithContext(context.Background(), http.MethodGet, resp.Header.Get("Location"), nil)
				if !assert.NoError(t, err) {
					return
				}

				resp, err = httpClient.Do(request)
				if !assert.NoError(t, err) {
					return
				}

				body, err := io.ReadAll(resp.Body)
				if !assert.NoError(t, err) {
					return
				}

				resp.Body.Close()

				if !tt.postAllow {
					assert.Equal(t, http.StatusForbidden, resp.StatusCode, logger.GetLogs(), string(body))

					return
				}

				if !assert.Equal(t, http.StatusOK, resp.StatusCode, logger.GetLogs(), string(body)) {
					return
				}

				_ = resp.Body.Close()

				if conf.HTTP.CallbackTemplate != config.Defaults.HTTP.CallbackTemplate {
					if !assert.Contains(t, string(body), "Permission is hereby granted") {
						return
					}
				}

				assert.NotEmpty(t, resp.Header.Get("Set-Cookie"))
				assert.Contains(t, resp.Header.Get("Set-Cookie"), "state=")
				assert.Contains(t, resp.Header.Get("Set-Cookie"), "Path=/oauth2/")
				assert.Contains(t, resp.Header.Get("Set-Cookie"), "HttpOnly")
				assert.Contains(t, resp.Header.Get("Set-Cookie"), "Max-Age=0")

				cancel()
			}()

			<-ctx.Done()

			client.Shutdown()
			wg.Wait()
		})
	}
}
