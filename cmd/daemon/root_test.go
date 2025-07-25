package daemon_test

import (
	"os"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/cmd/daemon"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/nettest"
)

func TestExecuteVersion(t *testing.T) {
	t.Parallel()

	logger := testutils.NewTestLogger()
	returnCode := daemon.Execute([]string{"", "--version"}, logger, make(chan os.Signal, 1))
	output := logger.String()

	assert.Equal(t, 0, returnCode, output)
}

func TestExecuteHelp(t *testing.T) {
	t.Parallel()

	logger := testutils.NewTestLogger()
	returnCode := daemon.Execute([]string{"openvpn-auth-oauth2", "--help"}, logger, make(chan os.Signal, 1))
	output := logger.String()

	assert.Equal(t, 0, returnCode, output)
	assert.Contains(t, output, "Usage of openvpn-auth-oauth2")
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
			"bad flag syntax: ---",
		},
		{
			"unknown args",
			[]string{"", "--http.asset-path"},
			"flag provided but not defined",
		},
		{
			"file not exists",
			[]string{"", "--config=nonexists", "--http.listen=127.0.0.1:0"},
			"configuration error: error opening config file nonexists: open nonexists: ",
		},
		{
			"invalid log format",
			[]string{
				"", "--config=../../config.example.yaml", "--log.format=invalid", "--log.level=warn", "--http.secret=" + testutils.Secret,
				"--http.listen=127.0.0.1:0",
			},
			"error setupConfiguration logging: unknown log format: invalid",
		},
		{
			"invalid log level",
			[]string{
				"", "--config=../../config.example.yaml", "--log.format=console", "--log.level=invalid", "--http.secret=" + testutils.Secret,
				"--http.listen=127.0.0.1:0",
			},
			`invalid value "invalid" for flag -log.level: slog: level string "invalid": unknown name`,
		},
		{
			"error oidc provider",
			[]string{
				"", "--config=../../config.example.yaml", "--log.format=console", "--log.level=info", "--http.secret=" + testutils.Secret,
				"--http.listen=127.0.0.1:0",
			},
			`error oidc provider`,
		},
		{
			"error oidc invalid provider",
			[]string{"", "--config=../../config.example.yaml", "--log.format=console", "--log.level=info", "--http.secret=" + testutils.Secret, "--http.listen=127.0.0.1:0", "--oauth2.provider=invalid"},
			`unknown oauth2 provider: invalid`,
		},
		{
			"error http listener",
			[]string{
				"", "--config=../../config.example.yaml", "--log.format=console", "--log.level=info", "--http.secret=" + testutils.Secret,
				"--http.listen=127.0.0.1:100000", "--oauth2.endpoint.token=http://127.0.0.1:10000/token", "--oauth2.endpoint.auth=http://127.0.0.1:10000/auth",
			},
			`error http listener: error http server listening: net.Listen: listen tcp: address 100000: invalid port`,
		},
		{
			"error http debug listener",
			[]string{
				"", "--config=../../config.example.yaml", "--log.format=console", "--log.level=info", "--http.secret=" + testutils.Secret,
				"--debug.pprof=true", "--debug.listen=127.0.0.1:100000", "--oauth2.endpoint.token=http://127.0.0.1:10000/token",
				"--oauth2.endpoint.auth=http://127.0.0.1:10000/auth", "--http.listen=127.0.0.1:0",
			},
			`error debug http listener: error http debug listening: net.Listen: listen tcp: address 100000: invalid port`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			managementInterface, err := nettest.NewLocalListener("tcp")
			require.NoError(t, err)

			t.Cleanup(func() {
				assert.NoError(t, managementInterface.Close())
			})

			logger := testutils.NewTestLogger()
			returnCode := daemon.Execute(append(tc.args, "--openvpn.addr=tcp://"+managementInterface.Addr().String()), logger, make(chan os.Signal, 1))
			output := logger.String()

			assert.Equal(t, 1, returnCode, output)
			assert.Contains(t, output, tc.err)
		})
	}
}
