package oauth2 //nolint:testpackage

import (
	"net/http"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/stretchr/testify/require"
)

func TestCheckClientIPAddrIPv6RemoteAddr(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	conf.HTTP.Check.IPAddr = true

	req := &http.Request{
		RemoteAddr: "[2001:db8::1]:12345",
		Header:     make(http.Header),
	}
	session := state.State{IPAddr: "2001:db8::1"}

	require.NoError(t, checkClientIPAddr(req, conf, session))
}
