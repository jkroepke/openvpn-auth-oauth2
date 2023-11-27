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
	var err error

	logger := c.logger.With(
		slog.Uint64("cid", client.Cid),
		slog.Uint64("kid", client.Kid),
		slog.String("reason", client.Reason),
		slog.String("common_name", client.CommonName),
		slog.String("username", client.Username),
	)

	logger.Info("new client connection")

	if c.checkAuthBypass(logger, client) || !c.checkClientSsoCapabilities(logger, client) {
		return nil
	}

	ClientIdentifier := state.ClientIdentifier{
		Cid: client.Cid,
		Kid: client.Kid,
	}

	commonName := utils.TransformCommonName(c.conf.OpenVpn.CommonName.Mode, client.CommonName)

	session := state.New(ClientIdentifier, client.IPAddr, commonName)
	if err = session.Encode(c.conf.HTTP.Secret); err != nil {
		return fmt.Errorf("error encoding state: %w", err)
	}

	startURL := utils.StringConcat(
		strings.TrimSuffix(c.conf.HTTP.BaseURL.String(), "/"),
		"/oauth2/start?state=", url.QueryEscape(session.Encoded()),
	)

	if len(startURL) >= 245 {
		c.DenyClient(logger, ClientIdentifier, "internal error")

		return fmt.Errorf("url %s (%d chars) too long! OpenVPN support up to 245 chars. Try --openvpn.common-name.mode to avoid this error",
			startURL, len(startURL))
	}

	logger.Info("start pending auth")

	_, err = c.SendCommandf(`client-pending-auth %d %d "WEB_AUTH::%s" %.0f`, client.Cid, client.Kid, startURL, c.conf.OpenVpn.AuthPendingTimeout.Seconds())
	if err != nil {
		logger.Warn(err.Error())
	}

	return nil
}

func (c *Client) checkAuthBypass(logger *slog.Logger, client connection.Client) bool {
	if !slices.Contains(c.conf.OpenVpn.Bypass.CommonNames, client.CommonName) {
		return false
	}

	logger.Info("client bypass authentication")

	if c.conf.OpenVpn.AuthTokenUser {
		tokenUsername := base64.StdEncoding.EncodeToString([]byte(client.CommonName))
		c.AcceptClientWithToken(logger, state.ClientIdentifier{Cid: client.Cid, Kid: client.Kid}, tokenUsername)
	} else {
		c.AcceptClient(logger, state.ClientIdentifier{Cid: client.Cid, Kid: client.Kid})
	}

	return true
}

func (c *Client) clientDisconnect(client connection.Client) {
	c.logger.Info("client disconnected",
		slog.Uint64("cid", client.Cid),
		slog.String("reason", client.Reason),
		slog.String("common_name", client.CommonName),
		slog.String("username", client.Username),
	)
}

func (c *Client) clientEstablished(client connection.Client) {
	c.logger.Info("client established",
		slog.Uint64("cid", client.Cid),
		slog.String("reason", client.Reason),
		slog.String("common_name", client.CommonName),
		slog.String("username", client.Username),
	)
}
