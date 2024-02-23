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

// clientConnect handles CONNECT events from OpenVPN management interface.
func (c *Client) clientConnect(client connection.Client) error {
	logger := c.logger.With(
		slog.Uint64("cid", client.CID),
		slog.Uint64("kid", client.KID),
		slog.String("common_name", client.CommonName),
		slog.String("reason", client.Reason),
		slog.String("session_id", client.SessionID),
		slog.String("session_state", client.SessionState),
	)

	logger.Info("new client connection")

	return c.handleClientAuthentication(logger, client)
}

// clientReauth handles REAUTH events from OpenVPN management interface.
func (c *Client) clientReauth(client connection.Client) error {
	logger := c.logger.With(
		slog.Uint64("cid", client.CID),
		slog.Uint64("kid", client.KID),
		slog.String("common_name", client.CommonName),
		slog.String("reason", client.Reason),
		slog.String("session_id", client.SessionID),
		slog.String("session_state", client.SessionState),
	)

	logger.Info("new client reauth")

	return c.handleClientAuthentication(logger, client)
}

// handleClientAuthentication holds the shared authentication logic for CONNECT and REAUTH events.
func (c *Client) handleClientAuthentication(logger *slog.Logger, client connection.Client) error {
	if c.checkAuthBypass(logger, client) ||
		!c.checkClientSsoCapabilities(logger, client) ||
		!c.checkAuthSessionState(logger, client) ||
		c.checkReauth(logger, client) {
		return nil
	}

	ClientIdentifier := state.ClientIdentifier{
		CID:       client.CID,
		KID:       client.KID,
		SessionID: client.SessionID,
	}

	commonName := utils.TransformCommonName(c.conf.OpenVpn.CommonName.Mode, client.CommonName)

	var ipAddr string
	if c.conf.OAuth2.Validate.IPAddr {
		ipAddr = client.IPAddr
	}

	session := state.New(ClientIdentifier, ipAddr, commonName)
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

	_, err := c.SendCommandf(`client-pending-auth %d %d "WEB_AUTH::%s" %.0f`, client.CID, client.KID, startURL, c.conf.OpenVpn.AuthPendingTimeout.Seconds())
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
	c.AcceptClient(logger, state.ClientIdentifier{CID: client.CID, KID: client.KID}, client.CommonName)

	return true
}

func (c *Client) checkReauth(logger *slog.Logger, client connection.Client) bool {
	if !c.conf.OAuth2.Refresh.Enabled {
		return false
	}

	if !(c.conf.OAuth2.Refresh.UseSessionID && (client.SessionState == "AuthenticatedEmptyUser" || client.SessionState == "Authenticated")) {
		return false
	}

	ok, err := c.oauth2.RefreshClientAuth(logger, client)
	if err != nil {
		logger.Warn(err.Error())
	}

	if ok {
		c.AcceptClient(logger, state.ClientIdentifier{CID: client.CID, KID: client.KID}, client.CommonName)
	}

	return ok
}

func (c *Client) checkAuthSessionState(logger *slog.Logger, client connection.Client) bool {
	if !c.conf.OAuth2.Refresh.UseSessionID || client.SessionID == "" { // SessionID is empty, we can't refresh
		return true
	}

	if client.SessionState == "Initial" || client.SessionState == "AuthenticatedEmptyUser" || client.SessionState == "Authenticated" {
		return true
	}

	logger.Warn("client session state invalid or expired. Denying client")

	c.DenyClient(logger, state.ClientIdentifier{CID: client.CID, KID: client.KID}, "session state invalid or expired")

	return false
}

func (c *Client) clientEstablished(client connection.Client) {
	c.logger.LogAttrs(context.Background(),
		slog.LevelInfo, "client established",
		slog.Uint64("cid", client.CID),
		slog.String("common_name", client.CommonName),
		slog.String("reason", client.Reason),
		slog.String("session_id", client.SessionID),
		slog.String("session_state", client.SessionState),
	)
}

func (c *Client) clientDisconnect(client connection.Client) {
	logger := c.logger.With(
		slog.Uint64("cid", client.CID),
		slog.String("common_name", client.CommonName),
		slog.String("reason", client.Reason),
		slog.String("session_id", client.SessionID),
		slog.String("session_state", client.SessionState),
	)

	logger.Info("client disconnected")

	c.oauth2.ClientDisconnect(logger, client)
}
