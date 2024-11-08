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
	logger := c.logger.With(
		slog.String("ip", fmt.Sprintf("%s:%s", client.IPAddr, client.IPPort)),
		slog.Uint64("cid", client.CID),
		slog.Uint64("kid", client.KID),
		slog.String("common_name", client.CommonName),
		slog.String("reason", client.Reason),
		slog.String("session_id", client.SessionID),
		slog.String("session_state", client.SessionState),
	)

	switch client.Reason {
	case "CONNECT", "REAUTH":
		c.handleClientAuthentication(logger, client)
	case "ESTABLISHED":
		c.clientEstablished(logger, client)
	case "DISCONNECT":
		c.clientDisconnect(logger, client)
	default:
		return fmt.Errorf("unknown client reason: %s", client.Reason)
	}

	return nil
}

// handleClientAuthentication holds the shared authentication logic for CONNECT and REAUTH events.
func (c *Client) handleClientAuthentication(logger *slog.Logger, client connection.Client) {
	logger.Info("new client authentication")

	// Check if the client is allowed to bypass authentication. If so, accept the client.
	if c.checkAuthBypass(client) {
		logger.Info("client bypass authentication")
		c.AcceptClient(logger, state.ClientIdentifier{CID: client.CID, KID: client.KID}, client.CommonName)

		return
	}

	// Check if the client supports SSO authentication via webauth.
	if !c.checkClientSsoCapabilities(client) {
		errorSsoNotSupported := "OpenVPN Client does not support SSO authentication via webauth"
		logger.Warn(errorSsoNotSupported)
		c.DenyClient(logger, state.ClientIdentifier{CID: client.CID, KID: client.KID}, errorSsoNotSupported)

		return
	}

	// Check if the client is already authenticated and refresh the client's authentication if enabled.
	// If the client is successfully re-authenticated, accept the client.
	if c.conf.OAuth2.Refresh.Enabled {
		ok, err := c.silentReAuthentication(logger, client)
		if err != nil {
			c.DenyClient(logger, state.ClientIdentifier{CID: client.CID, KID: client.KID}, ReasonStateExpiredOrInvalid)

			logger.Error("error refreshing client auth",
				slog.Any("err", err),
			)

			return
		} else if ok {
			c.AcceptClient(logger, state.ClientIdentifier{CID: client.CID, KID: client.KID}, client.CommonName)

			return
		}
	}

	// Start the authentication process for the client.
	if err := c.startClientAuth(logger, client); err != nil {
		// Deny the client if an error occurred during the authentication process.
		logger.Error("error starting client auth",
			slog.Any("err", err),
		)

		c.DenyClient(logger, state.ClientIdentifier{CID: client.CID, KID: client.KID}, "internal error")
	}
}

// startClientAuth initiates the authentication process for the client.
// The openvpn-auth-oauth2 plugin will send a client-pending-auth command to the OpenVPN management interface.
func (c *Client) startClientAuth(logger *slog.Logger, client connection.Client) error {
	clientIdentifier := state.ClientIdentifier{
		CID:       client.CID,
		KID:       client.KID,
		SessionID: client.SessionID,
	}

	commonName := utils.TransformCommonName(c.conf.OpenVpn.CommonName.Mode, client.CommonName)

	var (
		ipAddr string
		ipPort string
	)

	if c.conf.Log.VPNClientIP || c.conf.OAuth2.Validate.IPAddr {
		ipAddr = client.IPAddr
		ipPort = client.IPPort
	}

	session := state.New(clientIdentifier, ipAddr, ipPort, commonName, client.SessionState)

	encodedSession, err := session.Encode(c.conf.HTTP.Secret.String())
	if err != nil {
		return fmt.Errorf("error encoding state: %w", err)
	}

	startURL := utils.StringConcat(strings.TrimSuffix(c.conf.HTTP.BaseURL.String(), "/"), "/oauth2/start?state=", encodedSession)

	if len(startURL) >= 245 {
		return fmt.Errorf("url %s (%d chars) too long! OpenVPN support up to 245 chars. "+
			"Try --openvpn.common-name.mode=omit or --log.vpn-client-ip=false to avoid this error",
			startURL, len(startURL))
	}

	logger.Info("sent client-pending-auth command")

	_, err = c.SendCommandf(`client-pending-auth %d %d "WEB_AUTH::%s" %.0f`, client.CID, client.KID, startURL, c.conf.OpenVpn.AuthPendingTimeout.Seconds())
	if err != nil {
		return fmt.Errorf("error sending client-pending-auth command: %w", err)
	}

	return nil
}

func (c *Client) checkAuthBypass(client connection.Client) bool {
	return slices.Contains(c.conf.OpenVpn.Bypass.CommonNames, client.CommonName)
}

func (c *Client) silentReAuthentication(logger *slog.Logger, client connection.Client) (bool, error) {
	if c.conf.OAuth2.Refresh.UseSessionID {
		if client.SessionID == "" || !slices.Contains([]string{"Initial", "AuthenticatedEmptyUser", "Authenticated"}, client.SessionState) {
			return false, ErrClientSessionStateInvalidOrExpired
		}
	} else if client.SessionID != "" {
		logger.Warn("detected client session ID but not configured to use it. Please enable --oauth2.refresh.use-session-id")
	}

	ok, err := c.oauth2.RefreshClientAuth(logger, client)
	if err != nil {
		logger.Warn("error refreshing client auth", slog.Any("err", err))
	}

	return ok, nil
}

func (c *Client) clientEstablished(logger *slog.Logger, client connection.Client) {
	logger.LogAttrs(context.Background(),
		slog.LevelInfo, "client established",
		slog.String("vpn_ip", client.VPNAddress),
	)
}

func (c *Client) clientDisconnect(logger *slog.Logger, client connection.Client) {
	logger.Info("client disconnected")

	c.oauth2.ClientDisconnect(c.ctx, logger, client)
}
