package openvpn

import (
	"fmt"
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
)

func (c *Client) AcceptClient(logger *slog.Logger, client state.ClientIdentifier) {
	logger.Info(fmt.Sprintf("accept OpenVPN client cid %d, kid %d", client.Cid, client.Kid))

	_, err := c.SendCommandf(`client-auth-nt %d %d`, client.Cid, client.Kid)
	if err != nil {
		logger.Warn(err.Error())
	}
}

func (c *Client) AcceptClientWithToken(logger *slog.Logger, client state.ClientIdentifier, username string) {
	logger.Info(fmt.Sprintf("accept OpenVPN client cid %d, kid %d", client.Cid, client.Kid))

	_, err := c.SendCommandf("client-auth %d %d\npush \"auth-token-user %s\"\nEND", client.Cid, client.Kid, username)
	if err != nil {
		logger.Warn(err.Error())
	}
}

func (c *Client) DenyClient(logger *slog.Logger, client state.ClientIdentifier, reason string) {
	logger.Info(fmt.Sprintf("deny OpenVPN client cid %d, kid %d", client.Cid, client.Kid))

	_, err := c.SendCommandf(`client-deny %d %d "%s"`, client.Cid, client.Kid, reason)
	if err != nil {
		logger.Warn(err.Error())
	}
}
