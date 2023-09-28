package openvpn

import (
	"errors"
	"strconv"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
)

type ClientConnection struct {
	Kid    uint64
	Cid    uint64
	Reason string
	Env    map[string]string
}

func NewClientConnection(message string) (*ClientConnection, error) {
	clientConnection := &ClientConnection{
		Env: map[string]string{},
	}

	for _, line := range strings.Split(strings.TrimSpace(message), "\n") {
		if strings.HasPrefix(line, ">CLIENT:CONNECT") ||
			strings.HasPrefix(line, ">CLIENT:REAUTH") ||
			strings.HasPrefix(line, ">CLIENT:DISCONNECT") ||
			strings.HasPrefix(line, ">CLIENT:ESTABLISHED") ||
			strings.HasPrefix(line, ">CLIENT:CR_RESPONSE") {
			clientInfo := strings.Split(strings.TrimSpace(line), ",")
			if len(clientInfo) == 1 {
				return nil, errors.New(utils.StringConcat("unable to parse line ", line))
			}

			clientConnection.Reason = strings.Replace(clientInfo[0], ">CLIENT:", "", 1)

			if cid, err := strconv.ParseUint(clientInfo[1], 10, 64); err != nil {
				return nil, err
			} else {
				clientConnection.Cid = cid
			}

			if clientConnection.Reason != "DISCONNECT" && clientConnection.Reason != "ESTABLISHED" {
				if kid, err := strconv.ParseUint(clientInfo[2], 10, 64); err != nil {
					return nil, err
				} else {
					clientConnection.Kid = kid
				}
			}
		} else if strings.HasPrefix(line, ">CLIENT:ENV,") {
			clientEnv := strings.SplitN(strings.SplitN(line, ",", 2)[1], "=", 2)
			if clientEnv[0] == "END" {
				break
			} else if len(clientEnv) == 2 {
				clientConnection.Env[clientEnv[0]] = clientEnv[1]
			} else {
				clientConnection.Env[clientEnv[0]] = ""
			}
		}
	}

	if clientConnection.Reason == "" {
		return nil, errors.New("unable to parse client reason")
	}

	return clientConnection, nil
}
