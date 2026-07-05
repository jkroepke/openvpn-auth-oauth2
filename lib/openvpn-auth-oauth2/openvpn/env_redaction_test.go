//go:build (darwin || linux || openbsd || freebsd) && cgo

//nolint:testpackage
package openvpn

import (
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/lib/openvpn-auth-oauth2/util"
	"github.com/stretchr/testify/require"
)

func TestRedactedEnvList(t *testing.T) {
	t.Parallel()

	env := util.List{
		"common_name":   "alice@example.com",
		"device":        "tun0\nforged=true",
		"password":      "openvpn-password",
		"auth_token":    "auth-token",
		"client_secret": "client-secret",
		"bad\nkey":      "value",
	}

	redacted := redactedEnvList(env)

	require.Equal(t, "alice@example.com", redacted["common_name"])
	require.Equal(t, "tun0?forged=true", redacted["device"])
	require.Equal(t, redactedEnvValue, redacted["password"])
	require.Equal(t, redactedEnvValue, redacted["auth_token"])
	require.Equal(t, redactedEnvValue, redacted["client_secret"])
	require.Equal(t, "value", redacted["bad?key"])
	require.Equal(t, "openvpn-password", env["password"])
}
