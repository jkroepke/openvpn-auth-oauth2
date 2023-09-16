package openvpn

import (
	"strconv"
	"strings"
)

type ClientConnection struct {
	Kid    int
	Cid    int
	Reason string
	Env    map[string]string
}

func NewClientConnection(message string) (*ClientConnection, error) {
	clientConnection := &ClientConnection{
		Env: map[string]string{},
	}

	for _, line := range strings.Split(strings.TrimSpace(message), "\r\n") {
		if strings.HasPrefix(line, ">CLIENT:CONNECT") || strings.HasPrefix(line, ">CLIENT:REAUTH") || strings.HasPrefix(line, ">CLIENT:DISCONNECT") || strings.HasPrefix(line, ">CLIENT:ESTABLISHED") {
			clientInfo := strings.Split(strings.TrimSpace(line), ",")
			clientConnection.Reason = strings.Replace(clientInfo[0], ">CLIENT:", "", 1)

			if cid, err := strconv.Atoi(clientInfo[1]); err != nil {
				return nil, err
			} else {
				clientConnection.Cid = cid
			}

			if clientConnection.Reason != "DISCONNECT" && clientConnection.Reason != "ESTABLISHED" {
				if kid, err := strconv.Atoi(clientInfo[2]); err != nil {
					return nil, err
				} else {
					clientConnection.Kid = kid
				}
			}
		} else if strings.HasPrefix(line, ">CLIENT:ENV,") {
			clientEnv := strings.SplitN(strings.SplitN(line, ",", 2)[1], "=", 2)
			if len(clientEnv) == 2 {
				clientConnection.Env[clientEnv[0]] = clientEnv[1]
			} else {
				clientConnection.Env[clientEnv[0]] = ""
			}
		}
	}

	return clientConnection, nil
}
