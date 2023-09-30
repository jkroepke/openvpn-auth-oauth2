package cmd

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/zitadel/oidc/v2/example/server/storage"
	"github.com/zitadel/oidc/v2/pkg/op"
	"golang.org/x/text/language"
)

func TestExecuteVersion(t *testing.T) {
	os.Args = []string{"openvpn-auth-oauth2", "--version"}

	var buf bytes.Buffer
	_ = io.Writer(&buf)

	returnCode := Execute("version", "commit", "date", &buf)
	assert.Equal(t, 0, returnCode, buf.String())
}

func TestExecuteConfigInvalid(t *testing.T) {
	tests := []struct {
		name string
		args []string
		err  string
	}{
		{
			"file not exists",
			[]string{"openvpn-auth-oauth2", "--config=nonexists"},
			"error loading config: open nonexists: no such file or directory",
		},
		{
			"invalid log format",
			[]string{"openvpn-auth-oauth2", "--config=../config.example.yaml", "--log.format=invalid"},
			"error configure logger: Unknown log format: invalid",
		},
		{
			"invalid log level",
			[]string{"openvpn-auth-oauth2", "--config=../config.example.yaml", "--log.level=invalid"},
			`error configure logger: slog: level string \"invalid\": unknown name`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			_ = io.Writer(&buf)

			os.Args = tt.args

			returnCode := Execute("version", "commit", "date", &buf)
			assert.Equal(t, 1, returnCode, buf.String())
			assert.Contains(t, buf.String(), tt.err)
		})
	}
}

func TestExecuteConfigFileFound(t *testing.T) {
	opStorage := storage.NewStorage(storage.NewUserStore("http://localhost/"))
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

	handler, err := op.NewDynamicOpenIDProvider("", opConfig, opStorage,
		op.WithAllowInsecure(),
	)

	assert.NoError(t, err)
	svr := httptest.NewServer(handler.HttpHandler())

	l, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer l.Close()

	go func() {
		conn, err := l.Accept()
		assert.NoError(t, err)

		defer conn.Close() //nolint:errcheck
		reader := bufio.NewReader(conn)

		sendLine(t, conn, ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\r\n")
		assert.Equal(t, "hold release", readLine(t, reader))
		sendLine(t, conn, "SUCCESS: hold release succeeded\r\n")
		assert.Equal(t, "version", readLine(t, reader))

		sendLine(t, conn, "OpenVPN Version: OpenVPN Mock\r\nEND\r\n")

		time.Sleep(100 * time.Millisecond)

		p, err := os.FindProcess(os.Getpid())
		if err != nil {
			panic(err)
		}
		_ = p.Signal(syscall.SIGINT)
	}()

	t.Setenv("CONFIG_OPENVPN_ADDR", utils.StringConcat(l.Addr().Network(), "://", l.Addr().String()))
	t.Setenv("CONFIG_LOG_FORMAT", "console")

	os.Args = []string{
		"openvpn-auth-oauth2",
		"--config=../config.example.yaml",
		"--http.secret=0123456789101112",
		"--http.listen=127.0.0.1:0",
		"--oauth2.issuer", svr.URL,
	}

	var buf bytes.Buffer
	_ = io.Writer(&buf)

	returnCode := Execute("version", "commit", "date", &buf)
	assert.Equal(t, 0, returnCode, buf.String())
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
