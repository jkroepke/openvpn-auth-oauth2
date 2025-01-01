package openvpn

import (
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
)

func (c *Client) AcceptClient(logger *slog.Logger, client state.ClientIdentifier, username string) {
	logger.Info(fmt.Sprintf("accept OpenVPN client cid %d, kid %d", client.CID, client.KID))

	var (
		err           error
		tokenUsername string
	)

	if c.conf.OpenVpn.AuthTokenUser && client.UsernameIsDefined == 0 {
		tokenUsername = base64.StdEncoding.EncodeToString([]byte(username))
		if tokenUsername == "" {
			tokenUsername = "dXNlcm5hbWUK" // "username" //nolint:gosec // No hardcoded credentials
		}
	}

	clientConfig, err := c.readClientConfig(username)
	if err != nil {
		logger.Warn("failed to read client config",
			slog.Any("error", err),
		)
	}

	if tokenUsername != "" {
		clientConfig = append(clientConfig, fmt.Sprintf(`push "auth-token-user %s"`, tokenUsername))
	}

	if len(clientConfig) == 0 {
		_, err = c.SendCommandf(`client-auth-nt %d %d`, client.CID, client.KID)
	} else {
		sb := strings.Builder{}
		sb.WriteString(fmt.Sprintf("client-auth %d %d\r\n", client.CID, client.KID))

		for _, line := range clientConfig {
			sb.WriteString(strings.TrimSpace(line))
			sb.WriteString("\r\n")
		}

		sb.WriteString("END")

		_, err = c.SendCommand(sb.String(), false)
	}

	if err != nil {
		logger.Warn("failed to accept client",
			slog.Any("error", err),
		)
	}
}

func (c *Client) readClientConfig(username string) ([]string, error) {
	if c.ccdFS == nil || len(username) == 0 {
		return make([]string, 0), nil
	}

	clientConfigFile, err := c.ccdFS.Open(username + ".conf")
	if err != nil {
		return make([]string, 0), nil
	}

	clientConfigBytes, err := io.ReadAll(clientConfigFile)
	if err != nil {
		return make([]string, 0), fmt.Errorf("failed to read client config file: %w", err)
	}

	return strings.Split(strings.TrimSpace(string(clientConfigBytes)), "\n"), nil
}

func (c *Client) DenyClient(logger *slog.Logger, client state.ClientIdentifier, reason string) {
	logger.Info(fmt.Sprintf("deny OpenVPN client cid %d, kid %d", client.CID, client.KID))

	_, err := c.SendCommandf(`client-deny %d %d "%s"`, client.CID, client.KID, reason)
	if err != nil {
		logger.Warn("failed to deny client",
			slog.Any("error", err),
		)
	}
}
