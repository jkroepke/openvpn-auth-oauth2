package oauth2 //nolint:testpackage

import (
	"net/http"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
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

	require.NoError(t, checkClientIPAddr(req, &conf, session))
}

func TestCheckClientIPAddrProxyHeaders(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name           string
		remoteAddr     string
		trustedProxies []string
		sessionIP      string
		expectedErr    string
	}{
		{
			name:           "trusted proxy",
			remoteAddr:     "10.0.0.1:12345",
			trustedProxies: []string{"10.0.0.0/24"},
			sessionIP:      "127.0.0.1",
		},
		{
			name:           "untrusted proxy",
			remoteAddr:     "10.0.0.1:12345",
			trustedProxies: []string{"192.0.2.0/24"},
			sessionIP:      "127.0.0.1",
			expectedErr:    "client rejected: http client ip 10.0.0.1 and vpn ip 127.0.0.1 is different",
		},
		{
			name:           "trusted proxy with spoofed leading value",
			remoteAddr:     "10.0.0.1:12345",
			trustedProxies: []string{"10.0.0.0/24"},
			sessionIP:      "127.0.0.1",
			expectedErr:    "client rejected: http client ip 203.0.113.10 and vpn ip 127.0.0.1 is different",
		},
		{
			name:           "trusted proxy with multiple header values",
			remoteAddr:     "10.0.0.1:12345",
			trustedProxies: []string{"10.0.0.0/24"},
			sessionIP:      "203.0.113.10",
		},
		{
			name:           "trusted ipv6 proxy",
			remoteAddr:     "[2001:db8::2]:12345",
			trustedProxies: []string{"2001:db8::/64"},
			sessionIP:      "2001:db8::1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			conf := config.Defaults
			conf.HTTP.Check.IPAddr = true
			conf.HTTP.EnableProxyHeaders = true
			conf.HTTP.TrustedProxies = types.StringSlice(tc.trustedProxies)

			req := &http.Request{
				RemoteAddr: tc.remoteAddr,
				Header:     http.Header{"X-Forwarded-For": []string{"127.0.0.1, 10.0.0.1"}},
			}
			switch tc.name {
			case "trusted ipv6 proxy":
				req.Header.Set("X-Forwarded-For", "2001:db8::1, 2001:db8::2")
			case "trusted proxy with spoofed leading value":
				req.Header.Set("X-Forwarded-For", "127.0.0.1, 203.0.113.10")
			case "trusted proxy with multiple header values":
				req.Header = http.Header{
					"X-Forwarded-For": []string{"127.0.0.1", "203.0.113.10"},
				}
			}

			err := checkClientIPAddr(req, &conf, state.State{IPAddr: tc.sessionIP})
			if tc.expectedErr == "" {
				require.NoError(t, err)

				return
			}

			require.EqualError(t, err, tc.expectedErr)
		})
	}
}
