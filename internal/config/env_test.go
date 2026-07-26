package config //nolint:testpackage

import (
	"flag"
	"io"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadFromFlagAndEnvironment(t *testing.T) {
	t.Setenv("OPENVPN_AUTH_OAUTH2_HTTP_TLS", "true")
	t.Setenv("OPENVPN_AUTH_OAUTH2_OAUTH2_NONCE", "false")
	t.Setenv("OPENVPN_AUTH_OAUTH2_OPENVPN_COMMAND_TIMEOUT", "17s")
	t.Setenv("OPENVPN_AUTH_OAUTH2_OPENVPN_PASS_THROUGH_SOCKET_MODE", "0660")

	conf := Defaults
	require.NoError(t, conf.ReadFromFlagAndEnvironment([]string{"openvpn-auth-oauth2"}, io.Discard))

	assert.True(t, conf.HTTP.TLS)
	assert.False(t, conf.OAuth2.Nonce)
	assert.Equal(t, 17*time.Second, conf.OpenVPN.CommandTimeout)
	assert.Equal(t, types.FileMode(0o660), conf.OpenVPN.Passthrough.SocketMode)
}

func TestReadFromFlagAndEnvironmentRejectsNonBooleanEnvironmentValues(t *testing.T) {
	for _, value := range []string{"", "0", "1", "FALSE", "TRUE", "f", "t", "yes"} {
		t.Run(value, func(t *testing.T) {
			const environmentVariable = "OPENVPN_AUTH_OAUTH2_HTTP_TLS"

			t.Setenv(environmentVariable, value)

			conf := Defaults
			err := conf.ReadFromFlagAndEnvironment([]string{"openvpn-auth-oauth2"}, io.Discard)

			require.Error(t, err)
			require.ErrorContains(t, err, environmentVariable)
			require.ErrorContains(t, err, "true or false")
		})
	}
}

func TestReadFromFlagAndEnvironmentRejectsInvalidEnvironmentValues(t *testing.T) {
	for _, tc := range []struct {
		name                string
		environmentVariable string
		value               string
	}{
		{
			name:                "duration",
			environmentVariable: "OPENVPN_AUTH_OAUTH2_OPENVPN_COMMAND_TIMEOUT",
			value:               "eventually",
		},
		{
			name:                "log level",
			environmentVariable: "OPENVPN_AUTH_OAUTH2_LOG_LEVEL",
			value:               "verbose",
		},
		{
			name:                "file mode",
			environmentVariable: "OPENVPN_AUTH_OAUTH2_OPENVPN_PASS_THROUGH_SOCKET_MODE",
			value:               "660",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.environmentVariable, tc.value)

			conf := Defaults
			err := conf.ReadFromFlagAndEnvironment([]string{"openvpn-auth-oauth2"}, io.Discard)

			require.Error(t, err)
			require.ErrorContains(t, err, tc.environmentVariable)
		})
	}
}

func TestReadFromFlagAndEnvironmentRejectsUnknownEnvironmentVariable(t *testing.T) {
	const environmentVariable = "OPENVPN_AUTH_OAUTH2_HTTP_UNKNOWN"

	t.Setenv(environmentVariable, "true")

	conf := Defaults
	err := conf.ReadFromFlagAndEnvironment([]string{"openvpn-auth-oauth2"}, io.Discard)

	require.Error(t, err)
	require.ErrorContains(t, err, environmentVariable)
}

func TestApplyEnvironmentRejectsAmbiguousFlagNames(t *testing.T) {
	t.Parallel()

	flagSet := flag.NewFlagSet("test", flag.ContinueOnError)
	flagSet.String("ambiguous-name", "", "")
	flagSet.String("ambiguous.name", "", "")

	err := applyEnvironment(flagSet)

	require.Error(t, err)
	require.ErrorContains(t, err, "OPENVPN_AUTH_OAUTH2_AMBIGUOUS_NAME")
	require.ErrorContains(t, err, "ambiguous-name")
	require.ErrorContains(t, err, "ambiguous.name")
}

func TestReadFromFlagAndEnvironmentRejectsPositionalArguments(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{
		{"openvpn-auth-oauth2", "unexpected"},
		{"openvpn-auth-oauth2", "unexpected", "--http.tls"},
	} {
		conf := Defaults
		err := conf.ReadFromFlagAndEnvironment(args, io.Discard)

		require.Error(t, err)
		require.ErrorContains(t, err, "positional arguments")
	}
}

func TestGetEnvironmentVariableByFlagName(t *testing.T) {
	t.Parallel()

	require.Equal(t, "OPENVPN_AUTH_OAUTH2_CONFIG_FILE", getEnvironmentVariableByFlagName("config"))
	require.Equal(t,
		"OPENVPN_AUTH_OAUTH2_OPENVPN_PASS_THROUGH_SOCKET_MODE",
		getEnvironmentVariableByFlagName("openvpn.pass-through.socket-mode"))
}

func TestReadFromFlagAndEnvironmentIgnoresLegacyPrefix(t *testing.T) {
	t.Setenv("CONFIG_HTTP_LISTEN", ":9999")

	conf := Defaults
	require.NoError(t, conf.ReadFromFlagAndEnvironment([]string{"openvpn-auth-oauth2"}, io.Discard))
	assert.Equal(t, Defaults.HTTP.Listen, conf.HTTP.Listen)
}

func TestLookupConfigArgument(t *testing.T) {
	t.Setenv("OPENVPN_AUTH_OAUTH2_CONFIG_FILE", "environment.yaml")

	require.Equal(t, "environment.yaml", lookupConfigArgument([]string{"openvpn-auth-oauth2"}))
	require.Equal(t, "flag.yaml", lookupConfigArgument([]string{"openvpn-auth-oauth2", "--config", "flag.yaml"}))
	require.Equal(t, "flag.yaml", lookupConfigArgument([]string{"openvpn-auth-oauth2", "--config=flag.yaml"}))
	require.Empty(t, lookupConfigArgument([]string{"openvpn-auth-oauth2", "--config"}))
}
