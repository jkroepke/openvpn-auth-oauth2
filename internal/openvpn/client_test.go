package openvpn

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/stretchr/testify/assert"
)

func TestClient(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	l, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer l.Close()

	conf := &config.Config{
		Http: &config.Http{
			BaseUrl: "http://localhost/",
			Secret:  "0123456789101112",
		},
		OpenVpn: &config.OpenVpn{
			Addr:   fmt.Sprintf("%s://%s", l.Addr().Network(), l.Addr().String()),
			Bypass: &config.OpenVpnBypass{CommonNames: make([]string, 0)},
		},
	}

	client := NewClient(logger, conf)
	wg := sync.WaitGroup{}
	wg.Add(1)

	go func() {
		conn, err := l.Accept()
		assert.NoError(t, err)

		defer conn.Close() //nolint:errcheck

		reader := bufio.NewReader(conn)

		sendLine(t, conn, ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info:\r\n")
		assert.Equal(t, "hold release", readLine(t, reader))
		sendLine(t, conn, "SUCCESS: hold release succeeded\r\n")
		assert.Equal(t, "version", readLine(t, reader))

		sendLine(t, conn, "OpenVPN Version: OpenVPN Mock\r\nEND\r\n")
		sendLine(t, conn, ">CLIENT:CONNECT,0,1\r\n>CLIENT:ENV,daemon=0\r\n>CLIENT:ENV,END\r\n")
		assert.Equal(t, "client-deny 0 1 \"OpenVPN Client does not support SSO authentication via webauth\" \"OpenVPN Client does not support SSO authentication via webauth\"", readLine(t, reader))
		sendLine(t, conn, "SUCCESS: client-deny command succeeded\r\n")
		sendLine(t, conn, ">CLIENT:DISCONNECT,0\r\n>CLIENT:ENV,END\r\n")

		sendLine(t, conn, ">CLIENT:CONNECT,1,2\r\n>CLIENT:ENV,untrusted_ip=127.0.0.1\r\n>CLIENT:ENV,common_name=test\r\n>CLIENT:ENV,IV_SSO=webauth\r\n>CLIENT:ENV,END\r\n")
		pendingAuth := readLine(t, reader)
		assert.Contains(t, pendingAuth, "client-pending-auth 1 2 \"WEB_AUTH::")

		matches := regexp.MustCompile(`state=(.+)"`).FindStringSubmatch(pendingAuth)
		assert.Len(t, matches, 2)

		sessionState := state.NewEncoded(matches[1])
		err = sessionState.Decode(conf.Http.Secret)
		assert.NoError(t, err)

		assert.Equal(t, uint64(1), sessionState.Cid)
		assert.Equal(t, uint64(2), sessionState.Kid)
		assert.Equal(t, "test", sessionState.CommonName)
		assert.Equal(t, "127.0.0.1", sessionState.Ipaddr)

		client.Shutdown()

		wg.Done()
	}()
	err = client.Connect()
	assert.NoError(t, err)
	wg.Wait()
}

func sendLine(t *testing.T, conn net.Conn, msg string) {
	_, err := fmt.Fprint(conn, msg)
	assert.NoError(t, err)
}

func readLine(t *testing.T, reader *bufio.Reader) (msg string) {
	line, err := reader.ReadString('\n')
	assert.NoError(t, err)
	return strings.TrimSpace(line)
}
