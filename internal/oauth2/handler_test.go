package oauth2

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/zitadel/oidc/v2/example/server/storage"
	"github.com/zitadel/oidc/v2/pkg/op"
	"golang.org/x/text/language"
)

func TestHandler(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	confs := []struct {
		name          string
		conf          *config.Config
		ipaddr        string
		xForwardedFor string
		allow         bool
	}{
		{
			"default",
			&config.Config{
				Http: &config.Http{
					Secret: "0123456789101112",
					Check: &config.HttpCheck{
						IpAddr: false,
					},
				},
				Oauth2: &config.OAuth2{
					Provider:  "generic",
					Client:    &config.OAuth2Client{Id: "ID", Secret: "SECRET"},
					Endpoints: &config.OAuth2Endpoints{},
					Scopes:    []string{"openid", "profile"},
					Validate: &config.OAuth2Validate{
						Groups: make([]string, 0),
						Roles:  make([]string, 0),
						Issuer: true,
						IpAddr: false,
					},
				},
				OpenVpn: &config.OpenVpn{
					Bypass:        &config.OpenVpnBypass{CommonNames: []string{}},
					AuthTokenUser: true,
				},
			},
			"127.0.0.1",
			"",
			true,
		},
		{
			"with ipaddr",
			&config.Config{
				Http: &config.Http{
					Secret: "0123456789101112",
					Check: &config.HttpCheck{
						IpAddr: true,
					},
				},
				Oauth2: &config.OAuth2{
					Provider:  "generic",
					Client:    &config.OAuth2Client{Id: "ID", Secret: "SECRET"},
					Endpoints: &config.OAuth2Endpoints{},
					Scopes:    []string{"openid", "profile"},
					Validate: &config.OAuth2Validate{
						Groups: make([]string, 0),
						Roles:  make([]string, 0),
						Issuer: true,
						IpAddr: false,
					},
				},
				OpenVpn: &config.OpenVpn{
					Bypass:        &config.OpenVpnBypass{CommonNames: []string{}},
					AuthTokenUser: true,
				},
			},
			"127.0.0.1",
			"",
			true,
		},
		{
			"with ipaddr + forwarded-for",
			&config.Config{
				Http: &config.Http{
					Secret: "0123456789101112",
					Check: &config.HttpCheck{
						IpAddr: true,
					},
					EnableProxyHeaders: true,
				},
				Oauth2: &config.OAuth2{
					Provider:  "generic",
					Client:    &config.OAuth2Client{Id: "ID", Secret: "SECRET"},
					Endpoints: &config.OAuth2Endpoints{},
					Scopes:    []string{"openid", "profile"},
					Validate: &config.OAuth2Validate{
						Groups: make([]string, 0),
						Roles:  make([]string, 0),
						Issuer: true,
						IpAddr: false,
					},
				},
				OpenVpn: &config.OpenVpn{
					Bypass:        &config.OpenVpnBypass{CommonNames: []string{}},
					AuthTokenUser: true,
				},
			},
			"127.0.0.2",
			"127.0.0.2",
			true,
		},
		{
			"with ipaddr + disabled forwarded-for",
			&config.Config{
				Http: &config.Http{
					Secret: "0123456789101112",
					Check: &config.HttpCheck{
						IpAddr: true,
					},
					EnableProxyHeaders: false,
				},
				Oauth2: &config.OAuth2{
					Provider:  "generic",
					Client:    &config.OAuth2Client{Id: "ID", Secret: "SECRET"},
					Endpoints: &config.OAuth2Endpoints{},
					Scopes:    []string{"openid", "profile"},
					Validate: &config.OAuth2Validate{
						Groups: make([]string, 0),
						Roles:  make([]string, 0),
						Issuer: true,
						IpAddr: false,
					},
				},
				OpenVpn: &config.OpenVpn{
					Bypass:        &config.OpenVpnBypass{CommonNames: []string{}},
					AuthTokenUser: true,
				},
			},
			"127.0.0.2",
			"127.0.0.2",
			false,
		},
		{
			"with ipaddr + multiple forwarded-for",
			&config.Config{
				Http: &config.Http{
					Secret: "0123456789101112",
					Check: &config.HttpCheck{
						IpAddr: true,
					},
					EnableProxyHeaders: true,
				},
				Oauth2: &config.OAuth2{
					Provider:  "generic",
					Client:    &config.OAuth2Client{Id: "ID", Secret: "SECRET"},
					Endpoints: &config.OAuth2Endpoints{},
					Scopes:    []string{"openid", "profile"},
					Validate: &config.OAuth2Validate{
						Groups: make([]string, 0),
						Roles:  make([]string, 0),
						Issuer: true,
						IpAddr: false,
					},
				},
				OpenVpn: &config.OpenVpn{
					Bypass:        &config.OpenVpnBypass{CommonNames: []string{}},
					AuthTokenUser: true,
				},
			},
			"127.0.0.2",
			"127.0.0.2, 8.8.8.8",
			true,
		},
	}

	for _, tt := range confs {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			managementInterface, err := net.Listen("tcp", "127.0.0.1:0")
			assert.NoError(t, err)
			defer managementInterface.Close()

			clientListener, err := net.Listen("tcp", "127.0.0.1:0")
			assert.NoError(t, err)
			defer clientListener.Close()

			resourceServer, err := setupResourceServer(clientListener)
			assert.NoError(t, err)
			defer resourceServer.Close()

			resourceServerUrl, err := url.Parse(resourceServer.URL)
			assert.NoError(t, err)

			tt.conf.Oauth2.Issuer = resourceServerUrl
			tt.conf.Http.BaseUrl = &url.URL{Scheme: "http", Host: clientListener.Addr().String()}
			tt.conf.OpenVpn.Addr = &url.URL{Scheme: managementInterface.Addr().Network(), Host: managementInterface.Addr().String()}

			client := openvpn.NewClient(logger, tt.conf)
			defer client.Shutdown()

			provider, err := NewProvider(logger, tt.conf)
			if !assert.NoError(t, err) {
				return
			}

			httpClientListener := httptest.NewUnstartedServer(Handler(logger, provider, tt.conf, client))
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
				defer httpClientListener.Close()

				conn, err := managementInterface.Accept()
				assert.NoError(t, err)

				defer conn.Close() //nolint:errcheck
				reader := bufio.NewReader(conn)

				sendLine(t, conn, ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\r\n")
				assert.Equal(t, "hold release", readLine(t, reader))
				sendLine(t, conn, "SUCCESS: hold release succeeded\r\n")
				assert.Equal(t, "version", readLine(t, reader))

				sendLine(t, conn, "OpenVPN Version: OpenVPN Mock\r\nEND\r\n")

				if tt.allow {
					assert.Equal(t, "client-auth 0 1", readLine(t, reader))
					assert.Equal(t, "push \"auth-token-user aWQx\"", readLine(t, reader))
					assert.Equal(t, "END", readLine(t, reader))
				} else {
					assert.Equal(t, `client-deny 0 1 "client rejected"`, readLine(t, reader))
				}

				sendLine(t, conn, "SUCCESS: client-auth command succeeded\r\n")
			}()

			go func() {
				defer wg.Done()
				err := client.Connect()
				if err != nil && !strings.HasSuffix(err.Error(), "EOF") {
					assert.NoError(t, err)
				}
			}()

			jar, err := cookiejar.New(nil)
			if !assert.NoError(t, err) {
				return
			}

			httpClient.Jar = jar

			sessionState := state.New(0, 1, tt.ipaddr, "name")
			err = sessionState.Encode(tt.conf.Http.Secret)
			if !assert.NoError(t, err) {
				return
			}

			time.Sleep(time.Millisecond * 100)

			request, err := http.NewRequest("GET", fmt.Sprintf("%s/oauth2/start?state=%s", httpClientListener.URL, sessionState.Encoded), nil)
			if !assert.NoError(t, err) {
				return
			}

			if tt.xForwardedFor != "" {
				request.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}

			resp, err := httpClient.Do(request)
			if !assert.NoError(t, err) {
				return
			}

			body, err := io.ReadAll(resp.Body)
			if !assert.NoError(t, err) {
				return
			}
			_ = resp.Body.Close()

			expectedStatus := 200
			if !tt.allow {
				expectedStatus = 403
			}

			if !assert.Equal(t, expectedStatus, resp.StatusCode, string(body)) {
				return
			}

			client.Shutdown()
			wg.Wait()
		})
	}
}

func setupResourceServer(clientListener net.Listener) (*httptest.Server, error) {
	storage.RegisterClients(storage.WebClient("ID", "SECRET", fmt.Sprintf("http://%s/oauth2/callback", clientListener.Addr().String())))
	opStorage := storage.NewStorage(storage.NewUserStore("http://localhost"))
	opConfig := &op.Config{
		CryptoKey:                sha256.Sum256([]byte("test")),
		DefaultLogoutRedirectURI: "/",
		CodeMethodS256:           true,
		AuthMethodPost:           true,
		AuthMethodPrivateKeyJWT:  true,
		GrantTypeRefreshToken:    true,
		RequestObjectSupported:   true,
		SupportedUILocales:       []language.Tag{language.English},
	}

	opProvider, err := op.NewDynamicOpenIDProvider("", opConfig, opStorage,
		op.WithAllowInsecure(),
	)

	if err != nil {
		return nil, err
	}

	router := mux.NewRouter()
	router.PathPrefix("/login/username").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = opStorage.CheckUsernamePassword("test-user@localhost", "verysecure", r.FormValue("authRequestID"))
		http.Redirect(w, r, op.AuthCallbackURL(opProvider)(r.Context(), r.FormValue("authRequestID")), http.StatusFound)
	})
	router.PathPrefix("/").Handler(opProvider.HttpHandler())

	svr := httptest.NewServer(router)
	return svr, err
}

func sendLine(t *testing.T, conn net.Conn, msg string, a ...any) {
	_, err := fmt.Fprintf(conn, msg, a...)
	assert.NoError(t, err)
}

func readLine(t *testing.T, reader *bufio.Reader) (msg string) {
	line, err := reader.ReadString('\n')
	assert.NoError(t, err)
	return strings.TrimSpace(line)
}
