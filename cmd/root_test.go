package cmd_test

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/cmd"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/jkroepke/openvpn-auth-oauth2/pkg/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			"error loading config: file provider: open nonexists: no such file or directory",
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
		{
			"error oidc provider",
			[]string{"", "--config=../config.example.yaml", "--log.format=console", "--log.level=info", "--http.secret=1234567891111213"},
			`newProviderWithDiscovery`,
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
	clientListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer clientListener.Close()

	svr, client, err := testutils.SetupResourceServer(clientListener)
	require.NoError(t, err)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	defer l.Close()

	go func() {
		conn, err := l.Accept()
		require.NoError(t, err)

		defer conn.Close()
		reader := bufio.NewReader(conn)

		testutils.SendLine(t, conn, ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\r\n")
		assert.Equal(t, "hold release", testutils.ReadLine(t, reader))
		testutils.SendLine(t, conn, "SUCCESS: hold release succeeded\r\n")
		assert.Equal(t, "version", testutils.ReadLine(t, reader))

		testutils.SendLine(t, conn, "OpenVPN Version: OpenVPN Mock\r\nManagement Interface Version: 5\r\nEND\r\n")

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
		"--oauth2.client.id", client.ID,
	}

	var buf bytes.Buffer
	_ = io.Writer(&buf)

	returnCode := cmd.Execute(args, &buf, "version", "commit", "date")
	assert.Equal(t, 0, returnCode, buf.String())
}
