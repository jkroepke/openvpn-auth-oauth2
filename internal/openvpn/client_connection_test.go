package openvpn_test

import (
	"strings"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn"
	"github.com/stretchr/testify/assert"
)

func TestNewClientConnection(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name             string
		lines            []string
		clientConnection openvpn.ClientConnection
		err              string
	}{
		{
			"client CONNECT",
			[]string{">CLIENT:CONNECT,0,1", ">CLIENT:ENV,name1=val1", ">CLIENT:ENV,name2=", ">CLIENT:ENV,END"},
			openvpn.ClientConnection{Cid: 0, Kid: 1, Reason: "CONNECT", Env: map[string]string{
				"name1": "val1", "name2": "",
			}},
			"",
		},
		{
			"client CONNECT invalid cid",
			[]string{">CLIENT:CONNECT,k,2", ">CLIENT:ENV,name1=val1", ">CLIENT:ENV,name2=", ">CLIENT:ENV,END"},
			openvpn.ClientConnection{Cid: 1, Kid: 2, Reason: "CONNECT", Env: map[string]string{
				"name1": "val1", "name2": "",
			}},
			"unable to parse cid: strconv.ParseUint: parsing \"k\": invalid syntax",
		},
		{
			"client CONNECT invalid kid",
			[]string{">CLIENT:CONNECT,1,k", ">CLIENT:ENV,name1=val1", ">CLIENT:ENV,name2=", ">CLIENT:ENV,END"},
			openvpn.ClientConnection{Cid: 1, Kid: 2, Reason: "CONNECT", Env: map[string]string{
				"name1": "val1", "name2": "",
			}},
			"unable to parse kid: strconv.ParseUint: parsing \"k\": invalid syntax",
		},
		{
			"client REAUTH",
			[]string{">CLIENT:REAUTH,1,2", ">CLIENT:ENV,name1=val1", ">CLIENT:ENV,name2=", ">CLIENT:ENV,END"},
			openvpn.ClientConnection{Cid: 1, Kid: 2, Reason: "REAUTH", Env: map[string]string{
				"name1": "val1", "name2": "",
			}},
			"",
		},
		{
			"client ESTABLISHED",
			[]string{">CLIENT:ESTABLISHED,1", ">CLIENT:ENV,name1=val1", ">CLIENT:ENV,name2=", ">CLIENT:ENV,END"},
			openvpn.ClientConnection{
				Cid: 1, Kid: 0, Reason: "ESTABLISHED", Env: map[string]string{
					"name1": "val1", "name2": "",
				},
			},
			"",
		},
		{
			"client DISCONNECT",
			[]string{">CLIENT:DISCONNECT,1", ">CLIENT:ENV,name1=val1", ">CLIENT:ENV,name2=", ">CLIENT:ENV,END"},
			openvpn.ClientConnection{
				Cid: 1, Kid: 0, Reason: "DISCONNECT", Env: map[string]string{
					"name1": "val1", "name2": "",
				},
			},
			"",
		},
		{
			"client CR_RESPONSE",
			[]string{">CLIENT:CR_RESPONSE,1,2,YmFzZTY0", ">CLIENT:ENV,name1=val1", ">CLIENT:ENV,END"},
			openvpn.ClientConnection{
				Cid: 1, Kid: 2, Reason: "CR_RESPONSE", Env: map[string]string{
					"name1": "val1",
				},
			},
			"",
		},
		{
			"client invalid reason",
			[]string{">CLIENT:unknown", ">CLIENT:ENV,name1=val1", ">CLIENT:ENV,name2", ">CLIENT:ENV,END"},
			openvpn.ClientConnection{},
			"unable to parse client reason from message: >CLIENT:unknown\n>CLIENT:ENV,name1=val1\n>CLIENT:ENV,name2\n>CLIENT:ENV,END",
		},
		{
			"client invalid reason",
			[]string{">CLIENT:CONNECT", ">CLIENT:ENV,name1=val1", ">CLIENT:ENV,name2", ">CLIENT:ENV,END"},
			openvpn.ClientConnection{},
			"unable to parse line '>CLIENT:CONNECT': message invalid",
		},
	} {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			message := strings.Join(tt.lines, "\n")

			clientConnection, err := openvpn.NewClientConnection(message)
			if tt.err == "" {
				assert.NoError(t, err)
				assert.Equal(t, tt.clientConnection, clientConnection)
			} else {
				assert.Error(t, err)
				assert.Equal(t, tt.err, err.Error())
			}
		})
	}
}
