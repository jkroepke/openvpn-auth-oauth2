package openvpn

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn/connection"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
)

func (c *Client) processClient(client connection.Client) error {
	switch client.Reason {
	case "CONNECT":
		return c.clientConnect(client)
	case "REAUTH":
		return c.clientReauth(client)
	case "ESTABLISHED":
		c.clientEstablished(client)
	case "DISCONNECT":
		c.clientDisconnect(client)
	default:
		return fmt.Errorf("unknown client reason: %s", client.Reason)
	}

	return nil
}

// clientConnect handles CONNECT events from OpenVPN management interface
func (c *Client) clientConnect(client connection.Client) error {
	logger := c.logger.With(
		slog.Uint64("cid", client.Cid),
		slog.Uint64("kid", client.Kid),
		slog.String("reason", client.Reason),
		slog.String("common_name", client.CommonName),
		slog.String("username", client.Username),
	)

	logger.Info("new client connection")

	return c.handleClientAuthentication(logger, client)
}

// clientReauth handles REAUTH events from OpenVPN management interface
func (c *Client) clientReauth(client connection.Client) error {
	logger := c.logger.With(
		slog.Uint64("cid", client.Cid),
		slog.Uint64("kid", client.Kid),
		slog.String("reason", client.Reason),
		slog.String("common_name", client.CommonName),
		slog.String("username", client.Username),
	)

	logger.Info("new client reauth")

	if c.checkReauth(logger, client) {
		return nil
	}

	return c.handleClientAuthentication(logger, client)
}

// handleClientAuthentication holds the shared authentication logic for CONNECT and REAUTH events
func (c *Client) handleClientAuthentication(logger *slog.Logger, client connection.Client) error {
	if c.checkAuthBypass(logger, client) || !c.checkClientSsoCapabilities(logger, client) {
		return nil
	}

	ClientIdentifier := state.ClientIdentifier{
		Cid: client.Cid,
		Kid: client.Kid,
	}

	commonName := utils.TransformCommonName(c.conf.OpenVpn.CommonName.Mode, client.CommonName)

	session := state.New(ClientIdentifier, client.IPAddr, commonName)
	if err := session.Encode(c.conf.HTTP.Secret.String()); err != nil {
		return fmt.Errorf("error encoding state: %w", err)
	}

	startURL := utils.StringConcat(strings.TrimSuffix(c.conf.HTTP.BaseURL.String(), "/"), "/oauth2/start?state=", session.Encoded())

	if len(startURL) >= 245 {
		c.DenyClient(logger, ClientIdentifier, "internal error")

		return fmt.Errorf("url %s (%d chars) too long! OpenVPN support up to 245 chars. Try --openvpn.common-name.mode to avoid this error",
			startURL, len(startURL))
	}

	logger.Info("start pending auth")

	_, err := c.SendCommandf(`client-pending-auth %d %d "WEB_AUTH::%s" %.0f`, client.Cid, client.Kid, startURL, c.conf.OpenVpn.AuthPendingTimeout.Seconds())
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
	c.AcceptClient(logger, state.ClientIdentifier{Cid: client.Cid, Kid: client.Kid}, client.CommonName)

	return true
}

func (c *Client) checkReauth(logger *slog.Logger, client connection.Client) bool {
	if !c.conf.OAuth2.Refresh.Enabled {
		return false
	}

	ok, err := c.oauth2.RefreshClientAuth(client.Cid, logger)
	if err != nil {
		logger.Warn(err.Error())
	}

	if ok {
		c.AcceptClient(logger, state.ClientIdentifier{Cid: client.Cid, Kid: client.Kid}, client.CommonName)
	}

	return ok
}

func (c *Client) clientEstablished(client connection.Client) {
	c.logger.LogAttrs(context.Background(),
		slog.LevelInfo, "client established",
		slog.Uint64("cid", client.Cid),
		slog.String("reason", client.Reason),
		slog.String("common_name", client.CommonName),
		slog.String("username", client.Username),
	)
}

func (c *Client) clientDisconnect(client connection.Client) {
	logger := c.logger.With(
		slog.Uint64("cid", client.Cid),
		slog.String("reason", client.Reason),
		slog.String("common_name", client.CommonName),
		slog.String("username", client.Username),
	)

	logger.Info("client disconnected")
	c.oauth2.ClientDisconnect(client.Cid, logger)
}
