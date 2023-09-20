package openvpn

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewClientConnection(t *testing.T) {
	for _, tt := range []struct {
		name             string
		lines            []string
		clientConnection *ClientConnection
		err              string
	}{
		{"client CONNECT", []string{">CLIENT:CONNECT,1,2", ">CLIENT:ENV,name1=val1", ">CLIENT:ENV,name2=", ">CLIENT:ENV,END"}, &ClientConnection{Cid: 1, Kid: 2, Reason: "CONNECT", Env: map[string]string{"name1": "val1", "name2": ""}}, ""},
		{"client CONNECT invalid cid", []string{">CLIENT:CONNECT,k,2", ">CLIENT:ENV,name1=val1", ">CLIENT:ENV,name2=", ">CLIENT:ENV,END"}, &ClientConnection{Cid: 1, Kid: 2, Reason: "CONNECT", Env: map[string]string{"name1": "val1", "name2": ""}}, "strconv.Atoi: parsing \"k\": invalid syntax"},
		{"client CONNECT invalid kid", []string{">CLIENT:CONNECT,1,k", ">CLIENT:ENV,name1=val1", ">CLIENT:ENV,name2=", ">CLIENT:ENV,END"}, &ClientConnection{Cid: 1, Kid: 2, Reason: "CONNECT", Env: map[string]string{"name1": "val1", "name2": ""}}, "strconv.Atoi: parsing \"k\": invalid syntax"},
		{"client REAUTH", []string{">CLIENT:REAUTH,1,2", ">CLIENT:ENV,name1=val1", ">CLIENT:ENV,name2=", ">CLIENT:ENV,END"}, &ClientConnection{Cid: 1, Kid: 2, Reason: "REAUTH", Env: map[string]string{"name1": "val1", "name2": ""}}, ""},
		{"client ESTABLISHED", []string{">CLIENT:ESTABLISHED,1", ">CLIENT:ENV,name1=val1", ">CLIENT:ENV,name2=", ">CLIENT:ENV,END"}, &ClientConnection{Cid: 1, Kid: 0, Reason: "ESTABLISHED", Env: map[string]string{"name1": "val1", "name2": ""}}, ""},
		{"client DISCONNECT", []string{">CLIENT:DISCONNECT,1", ">CLIENT:ENV,name1=val1", ">CLIENT:ENV,name2=", ">CLIENT:ENV,END"}, &ClientConnection{Cid: 1, Kid: 0, Reason: "DISCONNECT", Env: map[string]string{"name1": "val1", "name2": ""}}, ""},
		{"client CR_RESPONSE", []string{">CLIENT:CR_RESPONSE,1,2,YmFzZTY0", ">CLIENT:ENV,name1=val1", ">CLIENT:ENV,name2=", ">CLIENT:ENV,END"}, &ClientConnection{Cid: 1, Kid: 2, Reason: "CR_RESPONSE", Env: map[string]string{"name1": "val1", "name2": ""}}, ""},
		{"client invalid reason", []string{">CLIENT:unknown", ">CLIENT:ENV,name1=val1", ">CLIENT:ENV,name2", ">CLIENT:ENV,END"}, nil, "unable to parse client reason"},
		{"client invalid reason", []string{">CLIENT:CONNECT", ">CLIENT:ENV,name1=val1", ">CLIENT:ENV,name2", ">CLIENT:ENV,END"}, nil, "unable to parse line >CLIENT:CONNECT"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			message := strings.Join(tt.lines, "\r\n")

			clientConnection, err := NewClientConnection(message)
			if tt.err == "" {
				assert.NoError(t, err)
				assert.Equal(t, clientConnection, tt.clientConnection)
			} else {
				assert.Error(t, err)
				assert.Equal(t, err.Error(), tt.err)
			}
		})
	}
}
