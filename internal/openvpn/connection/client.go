package connection

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
)

type Client struct {
	Kid        uint64
	Cid        uint64
	Reason     string
	IPAddr     string
	CommonName string
	IvSSO      string
	Env        map[string]string
}

func (client *Client) GetUserName() string {
	commonName := client.CommonName
	if client.Env["username"] != "" {
		commonName = client.Env["username"]
	}

	return commonName
}

func NewClient(conf config.Config, message string) (Client, error) { //nolint:cyclop
	client := Client{
		Env: make(map[string]string),
	}

	var (
		err  error
		line string
	)

	ok := true
	clientMessage := message

	for ok {
		line, clientMessage, ok = strings.Cut(clientMessage, "\n")
		line = strings.TrimSpace(line)

		if client.Reason == "" && isClientReason(line) {
			client.Reason, client.Cid, client.Kid, err = parseClientReason(line)
			if err != nil {
				return Client{}, err
			}
		} else if strings.HasPrefix(line, ">CLIENT:ENV,") {
			envKey, envValue := parseClientEnv(line)
			if envKey == "" || envValue == "" {
				continue
			}
			client.Env[envKey] = envValue
			switch envKey {
			case "untrusted_ip":
				client.IPAddr = envValue
			case "untrusted_ip6":
				client.IPAddr = envValue
			case conf.OpenVpn.CommonName.EnvironmentVariableName:
				client.CommonName = envValue
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
