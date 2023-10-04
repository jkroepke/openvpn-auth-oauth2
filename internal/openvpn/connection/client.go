package connection

import (
	"fmt"
	"strconv"
	"strings"
)

type Client struct {
	Kid        uint64
	Cid        uint64
	Reason     string
	IPAddr     string
	CommonName string
	Username   string
	IvSSO      string
}

func NewClient(message string) (Client, error) {
	client := Client{}

	var err error

	for _, line := range strings.Split(strings.TrimSpace(message), "\n") {
		if isClientReason(line) {
			client.Reason, client.Cid, client.Kid, err = parseClientReason(line)
			if err != nil {
				return Client{}, err
			}
		} else if strings.HasPrefix(line, ">CLIENT:ENV,") {
			envKey, envValue := parseClientEnv(line)
			if envKey == "" || envValue == "" {
				break
			}

			switch envKey {
			case "untrusted_ip":
				client.IPAddr = envValue
			case "common_name":
				client.CommonName = envValue
			case "username":
				client.Username = envValue
			case "IV_SSO":
				client.IvSSO = envValue
			}
		}
	}

	if client.Reason == "" {
		return Client{}, fmt.Errorf("unable to parse client reason from message: %s", message)
	}

	return client, nil
}

func parseClientEnv(line string) (string, string) {
	clientEnv := strings.SplitN(strings.SplitN(line, ",", 2)[1], "=", 2)
	if clientEnv[0] == "END" {
		return "", ""
	}

	if len(clientEnv) == 1 {
		return clientEnv[0], ""
	}

	return clientEnv[0], clientEnv[1]
}

func parseClientReason(line string) (string, uint64, uint64, error) {
	clientInfo := strings.Split(strings.TrimSpace(line), ",")
	if len(clientInfo) == 1 {
		return "", 0, 0, fmt.Errorf("unable to parse line '%s': %w", line, ErrInvalidMessage)
	}

	reason := strings.Replace(clientInfo[0], ">CLIENT:", "", 1)
	if reason == "" {
		return "", 0, 0, fmt.Errorf("unable to parse client reason: %w", ErrEmptyClientReasons)
	}

	cid, err := strconv.ParseUint(clientInfo[1], 10, 64)
	if err != nil {
		return "", 0, 0, fmt.Errorf("unable to parse cid: %w", err)
	}

	kid := uint64(0)

	if reason != "DISCONNECT" && reason != "ESTABLISHED" {
		kid, err = strconv.ParseUint(clientInfo[2], 10, 64)
		if err != nil {
			return "", 0, 0, fmt.Errorf("unable to parse kid: %w", err)
		}
	}

	return reason, cid, kid, nil
}

func isClientReason(line string) bool {
	return strings.HasPrefix(line, ">CLIENT:CONNECT") ||
		strings.HasPrefix(line, ">CLIENT:REAUTH") ||
		strings.HasPrefix(line, ">CLIENT:DISCONNECT") ||
		strings.HasPrefix(line, ">CLIENT:ESTABLISHED") ||
		strings.HasPrefix(line, ">CLIENT:CR_RESPONSE")
}
