package connection

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
)

type Client struct {
	Reason            string
	IPAddr            string
	IPPort            string
	VPNAddress        string
	CommonName        string
	SessionID         string
	SessionState      string
	IvSSO             string
	KID               uint64
	CID               uint64
	UsernameIsDefined int
}

func NewClient(conf config.Config, message string) (Client, error) { //nolint:cyclop
	client := Client{}

	var (
		err  error
		line string
	)

	ok := true
	clientMessage := message

	for ok {
		line, clientMessage, ok = strings.Cut(clientMessage, "\r\n")
		line = strings.TrimSpace(line)

		switch {
		case strings.HasPrefix(line, ">CLIENT:ADDRESS"):
			client.VPNAddress, err = parseClientVPNAddress(line)
			if err != nil {
				return Client{}, err
			}
		case strings.HasPrefix(line, ">CLIENT:ENV,"):
			envKey, envValue := parseClientEnv(line)
			if envKey == "" || envValue == "" {
				continue
			}

			switch envKey {
			case "untrusted_ip":
				client.IPAddr = envValue
			case "untrusted_ip6":
				client.IPAddr = envValue
			case "untrusted_port":
				client.IPPort = envValue
			case conf.OpenVPN.CommonName.EnvironmentVariableName:
				client.CommonName = envValue
				if conf.OpenVPN.CommonName.EnvironmentVariableName == "username" {
					client.UsernameIsDefined = 1
				}
			case "IV_SSO":
				client.IvSSO = envValue
			case "session_id":
				client.SessionID = envValue
			case "session_state":
				client.SessionState = envValue
			case "username":
				client.UsernameIsDefined = 1
			}
		case client.Reason == "" && isClientReason(line):
			client.Reason, client.CID, client.KID, err = parseClientReason(line)
			if err != nil {
				return Client{}, err
			}
		}
	}

	if client.Reason == "" {
		return Client{}, fmt.Errorf("%w: %s", ErrParseErrorClientReason, message)
	}

	return client, nil
}

func parseClientVPNAddress(line string) (string, error) {
	vpnIP, found := strings.CutPrefix(line, ">CLIENT:ADDRESS,")
	if !found {
		return "", fmt.Errorf("unable to parse line: %s", line)
	}

	_, vpnIP, found = strings.Cut(vpnIP, ",")
	if !found {
		return "", fmt.Errorf("unable to parse line: %s", line)
	}

	vpnIP, _, found = strings.Cut(vpnIP, ",")
	if !found {
		return "", fmt.Errorf("unable to parse line: %s", line)
	}

	return vpnIP, nil
}

func parseClientEnv(line string) (string, string) {
	comma := strings.Index(line, ",") + 1
	key, value, ok := strings.Cut(line[comma:], "=")

	if value == "END" {
		return "", ""
	}

	if !ok {
		return key, ""
	}

	return key, value
}

func parseClientReason(line string) (string, uint64, uint64, error) {
	reason, clientIDs, ok := strings.Cut(line, ",")
	if !ok {
		return "", 0, 0, fmt.Errorf("unable to parse line '%s': %w", line, ErrInvalidMessage)
	}

	_, reason, ok = strings.Cut(reason, ":")
	if !ok || reason == "" {
		return "", 0, 0, fmt.Errorf("unable to parse client reason: %w", ErrEmptyClientReasons)
	}

	cidString, kidString, _ := strings.Cut(clientIDs, ",")

	cid, err := strconv.ParseUint(cidString, 10, 64)
	if err != nil {
		return "", 0, 0, fmt.Errorf("unable to parse cid: %w", err)
	}

	var kid uint64

	if reason == "DISCONNECT" || reason == "ESTABLISHED" {
		return reason, cid, kid, nil
	}

	// kidString could contain a CR_RESPONSE, cut it again
	kidString, _, _ = strings.Cut(kidString, ",")

	kid, err = strconv.ParseUint(kidString, 10, 64)
	if err != nil {
		return "", 0, 0, fmt.Errorf("unable to parse kid: %w", err)
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
