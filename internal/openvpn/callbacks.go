package openvpn

import (
	"encoding/base64"
	"fmt"
	"github.com/zitadel/oidc/v3/pkg/crypto"
	"log/slog"
	"strings"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
)

func (c *Client) AcceptClient(logger *slog.Logger, client state.ClientIdentifier, username string) {
	logger.Info(fmt.Sprintf("accept OpenVPN client cid %d, kid %d", client.Cid, client.Kid))

	var err error

	if c.conf.OpenVpn.AuthTokenUser {
		var cmds = []string{
			fmt.Sprintf(`client-auth %d %d`, client.Cid, client.Kid),
		}

		if client.AuthToken == "" {
			tokenUsername := base64.StdEncoding.EncodeToString([]byte(username))
			cmds = append(cmds, fmt.Sprintf("push \"auth-token-user %s\"", tokenUsername))
			encryptedBytes, err := crypto.EncryptBytesAES([]byte(fmt.Sprintf("%s|%d", tokenUsername, time.Now().Unix())), c.conf.HTTP.Secret.String())
			if err == nil {
				client.AuthToken = base64.StdEncoding.EncodeToString(encryptedBytes)
				cmds = append(cmds, fmt.Sprintf("push \"auth-token AUTH-TOKEN:%s\"", client.AuthToken))
			}
		}
		cmds = append(cmds, "END")
		_, err = c.SendCommandf(strings.Join(cmds, "\n"))
	} else {
		_, err = c.SendCommandf(`client-auth-nt %d %d`, client.Cid, client.Kid)
	}

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
