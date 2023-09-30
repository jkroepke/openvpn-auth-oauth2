package openvpn

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/stretchr/testify/assert"
)

func TestClientInvalidServer(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	conf := &config.Config{
		Http: &config.Http{
			BaseUrl: &url.URL{Scheme: "http", Host: "localhost"},
			Secret:  "0123456789101112",
		},
		OpenVpn: &config.OpenVpn{
			Addr:   &url.URL{Scheme: "tcp", Host: "0.0.0.0:1"},
			Bypass: &config.OpenVpnBypass{CommonNames: make([]string, 0)},
		},
	}
	client := NewClient(logger, conf)
	err := client.Connect()
	assert.Error(t, err)
	assert.Equal(t, "unable to connect to openvpn management interface tcp://0.0.0.0:1: dial tcp 0.0.0.0:1: connect: connection refused", err.Error())
}

func TestClientFull(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer l.Close()

	confs := []struct {
		name   string
		conf   *config.Config
		client string
		expect string
		err    error
	}{
		{
			"without password",
			&config.Config{
				Http: &config.Http{
					BaseUrl: &url.URL{Scheme: "http", Host: "localhost"},
					Secret:  "0123456789101112",
				},
				OpenVpn: &config.OpenVpn{
					Addr:   &url.URL{Scheme: l.Addr().Network(), Host: l.Addr().String()},
					Bypass: &config.OpenVpnBypass{CommonNames: make([]string, 0)},
				},
			},
			">CLIENT:CONNECT,1,2\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END\r\n",
			"client-pending-auth 1 2 \"WEB_AUTH::",
			nil,
		},
		{
			"with password",
			&config.Config{
				Http: &config.Http{
					BaseUrl: &url.URL{Scheme: "http", Host: "localhost"},
					Secret:  "0123456789101112",
				},
				OpenVpn: &config.OpenVpn{
					Addr:     &url.URL{Scheme: l.Addr().Network(), Host: l.Addr().String()},
					Bypass:   &config.OpenVpnBypass{CommonNames: make([]string, 0)},
					Password: "password",
				},
			},
			">CLIENT:CONNECT,1,2\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END\r\n",
			"client-pending-auth 1 2 \"WEB_AUTH::",
			nil,
		},
		{
			"with invalid state",
			&config.Config{
				Http: &config.Http{
					BaseUrl: &url.URL{Scheme: "http", Host: "localhost"},
					Secret:  "012345678910111",
				},
				OpenVpn: &config.OpenVpn{
					Addr:     &url.URL{Scheme: l.Addr().Network(), Host: l.Addr().String()},
					Bypass:   &config.OpenVpnBypass{CommonNames: make([]string, 0)},
					Password: "password",
				},
			},
			">CLIENT:CONNECT,1,2\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END\r\n",
			"",
			errors.New("OpenVPN management error: error encoding state: crypto/aes: invalid key size 15"),
		},
		{
			"client without IV_SSO",
			&config.Config{
				Http: &config.Http{
					BaseUrl: &url.URL{Scheme: "http", Host: "localhost"},
					Secret:  "0123456789101112",
				},
				OpenVpn: &config.OpenVpn{
					Addr:     &url.URL{Scheme: l.Addr().Network(), Host: l.Addr().String()},
					Bypass:   &config.OpenVpnBypass{CommonNames: make([]string, 0)},
					Password: "password",
				},
			},
			">CLIENT:CONNECT,0,1\r\n>CLIENT:ENV,daemon=0\r\n>CLIENT:ENV,END\r\n",
			"client-deny 0 1 \"OpenVPN Client does not support SSO authentication via webauth\" \"OpenVPN Client does not support SSO authentication via webauth",
			nil,
		},
		{
			"client bypass",
			&config.Config{
				Http: &config.Http{
					BaseUrl: &url.URL{Scheme: "http", Host: "localhost"},
					Secret:  "0123456789101112",
				},
				OpenVpn: &config.OpenVpn{
					Addr:     &url.URL{Scheme: l.Addr().Network(), Host: l.Addr().String()},
					Bypass:   &config.OpenVpnBypass{CommonNames: []string{"bypass"}},
					Password: "password",
				},
			},
			">CLIENT:CONNECT,0,1\r\n>CLIENT:ENV,common_name=bypass\r\n>CLIENT:ENV,END\r\n",
			"client-auth-nt 0 1",
			nil,
		},
		{
			"client established",
			&config.Config{
				Http: &config.Http{
					BaseUrl: &url.URL{Scheme: "http", Host: "localhost"},
					Secret:  "0123456789101112",
				},
				OpenVpn: &config.OpenVpn{
					Addr:     &url.URL{Scheme: l.Addr().Network(), Host: l.Addr().String()},
					Bypass:   &config.OpenVpnBypass{CommonNames: []string{"bypass"}},
					Password: "password",
				},
			},
			">CLIENT:ESTABLISHED,0\r\n>CLIENT:ENV,common_name=bypass\r\n>CLIENT:ENV,END\r\n",
			"",
			nil,
		},
		{
			"client disconnected",
			&config.Config{
				Http: &config.Http{
					BaseUrl: &url.URL{Scheme: "http", Host: "localhost"},
					Secret:  "0123456789101112",
				},
				OpenVpn: &config.OpenVpn{
					Addr:     &url.URL{Scheme: l.Addr().Network(), Host: l.Addr().String()},
					Bypass:   &config.OpenVpnBypass{CommonNames: []string{"bypass"}},
					Password: "password",
				},
			},
			">CLIENT:DISCONNECT,0\r\n>CLIENT:ENV,common_name=bypass\r\n>CLIENT:ENV,END\r\n",
			"",
			nil,
		},
		{
			"client invalid reason",
			&config.Config{
				Http: &config.Http{
					BaseUrl: &url.URL{Scheme: "http", Host: "localhost"},
					Secret:  "0123456789101112",
				},
				OpenVpn: &config.OpenVpn{
					Addr:     &url.URL{Scheme: l.Addr().Network(), Host: l.Addr().String()},
					Bypass:   &config.OpenVpnBypass{CommonNames: []string{"bypass"}},
					Password: "password",
				},
			},
			">CLIENT:FOO,0\r\n>CLIENT:ENV,common_name=bypass\r\n>CLIENT:ENV,END\r\n",
			"",
			errors.New("OpenVPN management error: unable to parse client reason"),
		},
	}

	for _, tt := range confs {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(logger, tt.conf)
			wg := sync.WaitGroup{}
			wg.Add(1)

			go func() {
				defer wg.Done()
				conn, err := l.Accept()
				assert.NoError(t, err)

				defer conn.Close() //nolint:errcheck
				defer client.Shutdown()

				reader := bufio.NewReader(conn)

				if tt.conf.OpenVpn.Password != "" {
					sendLine(t, conn, "ENTER PASSWORD:")
					assert.Equal(t, tt.conf.OpenVpn.Password, readLine(t, reader))
					sendLine(t, conn, "SUCCESS: password is correct\r\n")
				}

				sendLine(t, conn, ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\r\n")
				assert.Equal(t, "hold release", readLine(t, reader))
				sendLine(t, conn, "SUCCESS: hold release succeeded\r\n")
				assert.Equal(t, "version", readLine(t, reader))

				sendLine(t, conn, "OpenVPN Version: OpenVPN Mock\r\nEND\r\n")
				sendLine(t, conn, tt.client)
				if tt.err != nil {
					_, _ = reader.ReadString('\n')
					return
				} else if tt.expect == "" {
					return
				}

				auth := readLine(t, reader)
				assert.Contains(t, auth, tt.expect)
				sendLine(t, conn, "SUCCESS: %s command succeeded\r\n", strings.SplitN(auth, " ", 2)[0])

				if strings.Contains(auth, "client-deny") {
					sendLine(t, conn, ">CLIENT:DISCONNECT,0\r\n>CLIENT:ENV,END\r\n")
				} else if strings.Contains(auth, "WEB_AUTH::") {
					matches := regexp.MustCompile(`state=(.+)"`).FindStringSubmatch(auth)
					assert.Len(t, matches, 2)

					sessionState := state.NewEncoded(matches[1])
					err := sessionState.Decode(tt.conf.Http.Secret)
					assert.NoError(t, err)

					assert.Equal(t, uint64(1), sessionState.Cid)
					assert.Equal(t, uint64(2), sessionState.Kid)
					assert.Equal(t, "test", sessionState.CommonName)
					assert.Equal(t, "127.0.0.1", sessionState.Ipaddr)
				}
			}()

			err := client.Connect()
			if tt.err != nil {
				if assert.Error(t, err) {
					assert.Equal(t, tt.err.Error(), err.Error())
				}
				client.Shutdown()
			} else {
				wg.Wait()
				if err != nil && !strings.HasSuffix(err.Error(), "EOF") {
					assert.NoError(t, err)
				}
			}
		})
	}
}

func TestClientInvalidPassword(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer l.Close()

	conf := &config.Config{
		Http: &config.Http{
			BaseUrl: &url.URL{Scheme: "http", Host: "localhost"},
			Secret:  "0123456789101112",
		},
		OpenVpn: &config.OpenVpn{
			Addr:     &url.URL{Scheme: l.Addr().Network(), Host: l.Addr().String()},
			Bypass:   &config.OpenVpnBypass{CommonNames: make([]string, 0)},
			Password: "invalid",
		},
	}

	client := NewClient(logger, conf)

	go func() {
		conn, err := l.Accept()
		assert.NoError(t, err)

		defer conn.Close() //nolint:errcheck
		reader := bufio.NewReader(conn)

		sendLine(t, conn, "ENTER PASSWORD:")
		assert.Equal(t, conf.OpenVpn.Password, readLine(t, reader))
		sendLine(t, conn, "ERROR: bad password\r\n")

		_, _ = reader.ReadString('\n')
	}()

	err = client.Connect()
	if assert.Error(t, err) {
		assert.Equal(t, "wrong openvpn management interface password", err.Error())
	}
	client.Shutdown()
}

func sendLine(t testing.TB, conn net.Conn, msg string, a ...any) {
	_, err := fmt.Fprintf(conn, msg, a...)
	assert.NoError(t, err)
}

func readLine(t testing.TB, reader *bufio.Reader) (msg string) {
	line, err := reader.ReadString('\n')
	assert.NoError(t, err)
	return strings.TrimSpace(line)
}
