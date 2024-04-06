package daemon_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/cmd/daemon"
	"github.com/jkroepke/openvpn-auth-oauth2/pkg/testutils"
	"github.com/stretchr/testify/assert"
)

func TestExecuteVersion(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	_ = io.Writer(&buf)

	returnCode := daemon.Execute([]string{"", "--version"}, &buf, "version", "commit", "date")
	assert.Equal(t, 0, returnCode, buf.String())
}

func TestExecuteHelp(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer

	buf.Grow(16 << 20)
	_ = io.Writer(&buf)

	returnCode := daemon.Execute([]string{"openvpn-auth-oauth2-test", "--help"}, &buf, "version", "commit", "date")
	output := buf.String()

	assert.Equal(t, 0, returnCode, buf.String())
	assert.Contains(t, output, "Usage of openvpn-auth-oauth2-test")
	assert.Contains(t, output, "--version")
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
			[]string{"", "--config=../../config.example.yaml", "--log.format=invalid", "--log.level=warn", "--http.secret=" + testutils.Secret},
			"error configure logging: unknown log format: invalid",
		},
		{
			"invalid log level",
			[]string{"", "--config=../../config.example.yaml", "--log.format=console", "--log.level=invalid", "--http.secret=" + testutils.Secret},
			`error parsing cli args: invalid value \"invalid\" for flag -log.level: slog: level string \"invalid\": unknown name`,
		},
		{
			"error oidc provider",
			[]string{"", "--config=../../config.example.yaml", "--log.format=console", "--log.level=info", "--http.secret=" + testutils.Secret},
			`error oauth2 provider`,
		},
		{
			"error http listener",
			[]string{
				"", "--config=../../config.example.yaml", "--log.format=console", "--log.level=info", "--http.secret=" + testutils.Secret,
				"--http.listen=127.0.0.1:100000", "--oauth2.endpoint.token=http://127.0.0.1:10000/token", "--oauth2.endpoint.auth=http://127.0.0.1:10000/auth",
			},
			`error http listener: error http server listening: listen tcp: address 100000: invalid port`,
		},
		{
			"error http debug listener",
			[]string{
				"", "--config=../../config.example.yaml", "--log.format=console", "--log.level=info", "--http.secret=" + testutils.Secret,
				"--debug.pprof=true", "--debug.listen=127.0.0.1:100000", "--oauth2.endpoint.token=http://127.0.0.1:10000/token",
				"--oauth2.endpoint.auth=http://127.0.0.1:10000/auth",
			},
			`error debug http listener: error http debug listening: listen tcp: address 100000: invalid port`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var buf bytes.Buffer
			_ = io.Writer(&buf)

			returnCode := daemon.Execute(tt.args, &buf, "version", "commit", "date")

			assert.Equal(t, 1, returnCode, buf.String())
			assert.Contains(t, buf.String(), tt.err)
		})
	}
}
