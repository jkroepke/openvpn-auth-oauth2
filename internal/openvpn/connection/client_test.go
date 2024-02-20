package connection_test

import (
	"strings"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn/connection"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClientConnection(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name             string
		conf             config.Config
		lines            []string
		clientConnection connection.Client
		err              string
	}{
		{
			"client CONNECT",
			config.Defaults,
			[]string{
				">CLIENT:CONNECT,0,1",
				">CLIENT:ENV,common_name=common_name",
				">CLIENT:ENV,username=username",
				">CLIENT:ENV,untrusted_ip=127.0.0.1",
				">CLIENT:ENV,IV_SSO=webauth",
				">CLIENT:ENV,session_id=K3waLcCGyUuzkdXh",
				">CLIENT:ENV,END",
			},
			connection.Client{
				CID: 0, KID: 1, Reason: "CONNECT", CommonName: "common_name", IPAddr: "127.0.0.1", IvSSO: "webauth", SessionID: "K3waLcCGyUuzkdXh",
			},
			"",
		},
		{
			"client CONNECT ipv6",
			config.Defaults,
			[]string{
				">CLIENT:CONNECT,0,1",
				">CLIENT:ENV,common_name=common_name",
				">CLIENT:ENV,username=username",
				">CLIENT:ENV,untrusted_ip6=::1",
				">CLIENT:ENV,IV_SSO=webauth",
				">CLIENT:ENV,session_id=K3waLcCGyUuzkdXh",
				">CLIENT:ENV,END",
			},
			connection.Client{
				CID: 0, KID: 1, Reason: "CONNECT", CommonName: "common_name", IPAddr: "::1", IvSSO: "webauth", SessionID: "K3waLcCGyUuzkdXh",
			},
			"",
		},
		{
			"client CONNECT username-as-common-name",
			(func() config.Config {
				conf := config.Defaults
				conf.OpenVpn.CommonName.EnvironmentVariableName = "username"

				return conf
			})(),
			[]string{
				">CLIENT:CONNECT,0,1",
				">CLIENT:ENV,common_name=common_name",
				">CLIENT:ENV,username=username",
				">CLIENT:ENV,untrusted_ip=127.0.0.1",
				">CLIENT:ENV,IV_SSO=webauth",
				">CLIENT:ENV,END",
			},
			connection.Client{
				CID: 0, KID: 1, Reason: "CONNECT", CommonName: "username", IPAddr: "127.0.0.1", IvSSO: "webauth",
			},
			"",
		},
		{
			"client CONNECT invalid cid",
			config.Defaults,
			[]string{">CLIENT:CONNECT,k,2", ">CLIENT:ENV,name1=val1", ">CLIENT:ENV,name2=", ">CLIENT:ENV,END"},
			connection.Client{CID: 1, KID: 2, Reason: "CONNECT"},
			"unable to parse cid: strconv.ParseUint: parsing \"k\": invalid syntax",
		},
		{
			"client CONNECT invalid kid",
			config.Defaults,
			[]string{">CLIENT:CONNECT,1,k", ">CLIENT:ENV,name1=val1", ">CLIENT:ENV,name2=", ">CLIENT:ENV,END"},
			connection.Client{CID: 1, KID: 2, Reason: "CONNECT"},
			"unable to parse kid: strconv.ParseUint: parsing \"k\": invalid syntax",
		},
		{
			"client REAUTH",
			config.Defaults,
			[]string{">CLIENT:REAUTH,1,2", ">CLIENT:ENV,common_name=common_name", ">CLIENT:ENV,name2=", ">CLIENT:ENV,END"},
			connection.Client{CID: 1, KID: 2, Reason: "REAUTH", CommonName: "common_name"},
			"",
		},
		{
			"client ESTABLISHED",
			config.Defaults,
			[]string{">CLIENT:ESTABLISHED,1", ">CLIENT:ENV,END"},
			connection.Client{CID: 1, KID: 0, Reason: "ESTABLISHED"},
			"",
		},
		{
			"client DISCONNECT",
			config.Defaults,
			[]string{">CLIENT:DISCONNECT,1", ">CLIENT:ENV,name1=val1", ">CLIENT:ENV,name2=", ">CLIENT:ENV,END"},
			connection.Client{CID: 1, KID: 0, Reason: "DISCONNECT"},
			"",
		},
		{
			"client CR_RESPONSE",
			config.Defaults,
			[]string{">CLIENT:CR_RESPONSE,1,2,YmFzZTY0", ">CLIENT:ENV,name1=val1", ">CLIENT:ENV,END"},
			connection.Client{
				CID: 1, KID: 2, Reason: "CR_RESPONSE",
			},
			"",
		},
		{
			"client invalid reason",
			config.Defaults,
			[]string{">CLIENT:unknown", ">CLIENT:ENV,name1=val1", ">CLIENT:ENV,name2", ">CLIENT:ENV,END"},
			connection.Client{},
			"unable to parse client reason from message: >CLIENT:unknown\n>CLIENT:ENV,name1=val1\n>CLIENT:ENV,name2\n>CLIENT:ENV,END",
		},
		{
			"client invalid reason",
			config.Defaults,
			[]string{">CLIENT:CONNECT", ">CLIENT:ENV,name1=val1", ">CLIENT:ENV,name2", ">CLIENT:ENV,END"},
			connection.Client{},
			"unable to parse line '>CLIENT:CONNECT': message invalid",
		},
	} {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			message := strings.Join(tt.lines, "\n")

			clientConnection, err := connection.NewClient(tt.conf, message)
			if tt.err == "" {
				require.NoError(t, err)
				assert.Equal(t, tt.clientConnection, clientConnection)
			} else {
				require.Error(t, err)
				assert.Equal(t, tt.err, err.Error())
			}
		})
	}
}
