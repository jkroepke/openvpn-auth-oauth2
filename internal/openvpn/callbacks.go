package openvpn

import (
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
)

func (c *Client) AcceptClient(logger *slog.Logger, client state.ClientIdentifier) {
	_, err := c.SendCommandf(`client-auth-nt %d %d`, client.Cid, client.Kid)
	if err != nil {
		logger.Warn(err.Error())
	}
}

func (c *Client) AcceptClientWithToken(logger *slog.Logger, client state.ClientIdentifier, username string) {
	_, err := c.SendCommandf("client-auth %d %d\npush \"auth-token-user %s\"\nEND", client.Cid, client.Kid, username)
	if err != nil {
		logger.Warn(err.Error())
	}
}

func (c *Client) DenyClient(logger *slog.Logger, client state.ClientIdentifier, reason string) {
	_, err := c.SendCommandf(`client-deny %d %d "%s"`, client.Cid, client.Kid, reason)
	if err != nil {
		logger.Warn(err.Error())
	}
}
