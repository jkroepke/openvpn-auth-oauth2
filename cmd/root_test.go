package cmd_test

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

	"github.com/jkroepke/openvpn-auth-oauth2/cmd"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/zitadel/oidc/v2/example/server/storage"
	"github.com/zitadel/oidc/v2/pkg/op"
	"golang.org/x/text/language"
)

func TestExecuteVersion(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	_ = io.Writer(&buf)

	returnCode := cmd.Execute([]string{"", "--version"}, &buf, "version", "commit", "date")
	assert.Equal(t, 0, returnCode, buf.String())
}
func TestExecuteConfigInvalid(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		err  string
	}{
		{
			"invalid args",
			[]string{"", "---"},
			"error parsing cli args: bad flag syntax: ---",
		},
		{
			"file not exists",
			[]string{"", "--config=nonexists"},
			"error loading config: error from file provider: open nonexists: no such file or directory",
		},
		{
			"invalid log format",
			[]string{"", "--config=../config.example.yaml", "--log.format=invalid", "--log.level=warn", "--http.secret=1234567891011213"},
			"error configure logging: unknown log format: invalid",
		},
		{
			"invalid log level",
			[]string{"", "--config=../config.example.yaml", "--log.format=console", "--log.level=invalid", "--http.secret=1234567891111213"},
			`error configure logging: unable to parse log level: slog: level string \"invalid\": unknown name`,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			_ = io.Writer(&buf)

			returnCode := cmd.Execute(tt.args, &buf, "version", "commit", "date")
			assert.Equal(t, 1, returnCode, buf.String())
			assert.Contains(t, buf.String(), tt.err)
		})
	}
}

func TestExecuteConfigFileFound(t *testing.T) { //nolint: paralleltest
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

		defer conn.Close()
		reader := bufio.NewReader(conn)

		sendLine(t, conn, ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\r\n")
		assert.Equal(t, "hold release", readLine(t, reader))
		sendLine(t, conn, "SUCCESS: hold release succeeded\r\n")
		assert.Equal(t, "version", readLine(t, reader))

		sendLine(t, conn, "OpenVPN Version: OpenVPN Mock\r\nManagement Interface Version: 5\r\nEND\r\n")

		time.Sleep(100 * time.Millisecond)

		p, err := os.FindProcess(os.Getpid())
		if err != nil {
			panic(err)
		}

		_ = p.Signal(syscall.SIGINT)
	}()

	t.Setenv("CONFIG_OPENVPN_ADDR", utils.StringConcat(l.Addr().Network(), "://", l.Addr().String()))
	t.Setenv("CONFIG_LOG_FORMAT", "console")
	t.Setenv("CONFIG_LOG_LEVEL", "warn")

	args := []string{
		"openvpn-auth-oauth2",
		"--config=../config.example.yaml",
		"--http.secret=0123456789101112",
		"--http.listen=127.0.0.1:0",
		"--oauth2.issuer", svr.URL,
	}

	var buf bytes.Buffer
	_ = io.Writer(&buf)

	returnCode := cmd.Execute(args, &buf, "version", "commit", "date")
	assert.Equal(t, 0, returnCode, buf.String())
}

func sendLine(tb testing.TB, conn net.Conn, msg string, a ...any) {
	tb.Helper()

	_, err := fmt.Fprintf(conn, msg, a...)
	assert.NoError(tb, err)
}

func readLine(tb testing.TB, reader *bufio.Reader) string {
	tb.Helper()

	line, err := reader.ReadString('\n')
	assert.NoError(tb, err)

	return strings.TrimSpace(line)
}
