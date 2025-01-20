package openvpn

import (
	"encoding/base64"
	"fmt"
	"log/slog"

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

	if tokenUsername == "" {
		_, err = c.SendCommandf(`client-auth-nt %d %d`, client.CID, client.KID)
	} else {
		_, err = c.SendCommandf("client-auth %d %d\r\noverride-username \"%s\"\r\npush \"auth-token-user %s\"\r\nEND", client.CID, client.KID, username, tokenUsername)
	}

	if err != nil {
		logger.Warn("failed to accept client",
			slog.Any("error", err),
		)
	}
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
