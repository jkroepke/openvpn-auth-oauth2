package openvpn

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn/connection"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
)

func (c *Client) processClient(client connection.Client) error {
	switch client.Reason {
	case "CONNECT":
		fallthrough
	case "REAUTH":
		return c.clientConnect(client)
	case "ESTABLISHED":
		c.clientEstablished(client)
	case "DISCONNECT":
		c.clientDisconnect(client)
	default:
		return fmt.Errorf("unknown client reason: %s", client.Reason)
	}

	return nil
}

func (c *Client) clientConnect(client connection.Client) error {
	logger := c.logger.With(
		slog.Uint64("cid", client.Cid),
		slog.Uint64("kid", client.Kid),
		slog.String("reason", client.Reason),
		slog.String("common_name", client.Env["common_name"]),
		slog.String("username", client.Env["username"]),
	)

	logger.Info("new client connection")

	if val, ok := client.Env["common_name"]; ok && slices.Contains(c.conf.OpenVpn.Bypass.CommonNames, val) {
		logger.Info("client bypass authentication")

		var err error

		if c.conf.OpenVpn.AuthTokenUser {
			tokenUsername := base64.StdEncoding.EncodeToString([]byte(client.Env["common_name"]))
			_, err = c.SendCommandf("client-auth %d %d\npush \"auth-token-user %s\"\nEND", client.Cid, client.Kid, tokenUsername)
		} else {
			_, err = c.SendCommandf("client-auth-nt %d %d", client.Cid, client.Kid)
		}

		if err != nil {
			logger.Warn(err.Error())
		}

		return nil
	}

	if !c.checkClientSsoCapabilities(logger, client) {
		return nil
	}

	session := state.New(client.Cid, client.Kid, client.Env["untrusted_ip"], client.Env["common_name"])
	if err := session.Encode(c.conf.HTTP.Secret); err != nil {
		return fmt.Errorf("error encoding state: %w", err)
	}

	startURL := utils.StringConcat(
		strings.TrimSuffix(c.conf.HTTP.BaseURL.String(), "/"),
		"/oauth2/start?state=", url.QueryEscape(session.Encoded()),
	)

	logger.Info("start pending auth")

	_, err := c.SendCommandf(`client-pending-auth %d %d "WEB_AUTH::%s" %d`, client.Cid, client.Kid, startURL, 600)
	if err != nil {
		logger.Warn(err.Error())
	}

	return nil
}

func (c *Client) clientDisconnect(client connection.Client) {
	c.logger.Info("client disconnected",
		slog.Uint64("cid", client.Cid),
		slog.String("reason", client.Reason),
		slog.String("common_name", client.Env["common_name"]),
		slog.String("username", client.Env["username"]),
	)
}

func (c *Client) clientEstablished(client connection.Client) {
	c.logger.Info("client established",
		slog.Uint64("cid", client.Cid),
		slog.String("reason", client.Reason),
		slog.String("common_name", client.Env["common_name"]),
		slog.String("username", client.Env["username"]),
	)
}
