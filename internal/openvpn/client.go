package openvpn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn/connection"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
)

func (c *Client) processClient(ctx context.Context, client connection.Client) error {
	logger := c.logger.With(
		slog.String("ip", fmt.Sprintf("%s:%s", client.IPAddr, client.IPPort)),
		slog.Uint64("cid", client.CID),
		slog.Uint64("kid", client.KID),
		slog.String("common_name", client.CommonName),
		slog.String("reason", client.Reason),
		slog.String("session_id", client.SessionID),
		slog.String("session_state", client.SessionState),
	)

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	switch client.Reason {
	case "CONNECT", "REAUTH":
		c.handleClientAuthentication(ctx, logger, client)
	case "ESTABLISHED":
		c.clientEstablished(ctx, logger, client)
	case "DISCONNECT":
		c.clientDisconnect(ctx, logger, client)
	default:
		return fmt.Errorf("%w: %s", ErrUnknownClientReason, client.Reason)
	}

	return nil
}

// handleClientAuthentication holds the shared authentication logic for CONNECT and REAUTH events.
func (c *Client) handleClientAuthentication(ctx context.Context, logger *slog.Logger, client connection.Client) {
	logger.LogAttrs(ctx, slog.LevelInfo, "new client authentication")

	// Check if the client is allowed to bypass authentication. If so, accept the client.
	if c.checkAuthBypass(client) {
		logger.LogAttrs(ctx, slog.LevelInfo, "client bypass authentication")
		c.AcceptClient(logger, state.ClientIdentifier{CID: client.CID, KID: client.KID}, client.CommonName)

		return
	}

	// Check if the client supports SSO authentication via webauth.
	if !c.checkClientSsoCapabilities(client) {
		errorSsoNotSupported := "OpenVPN Client does not support SSO authentication via webauth"
		logger.LogAttrs(ctx, slog.LevelWarn, errorSsoNotSupported)
		c.DenyClient(logger, state.ClientIdentifier{CID: client.CID, KID: client.KID}, errorSsoNotSupported)

		return
	}

	// Check if the client is already authenticated and refresh the client's authentication if enabled.
	// If the client is successfully re-authenticated, accept the client.
	ok, err := c.silentReAuthentication(ctx, logger, client)
	if err != nil {
		c.DenyClient(logger, state.ClientIdentifier{CID: client.CID, KID: client.KID}, ReasonStateExpiredOrInvalid)

		logger.LogAttrs(ctx, slog.LevelError, "error refreshing client auth",
			slog.Any("err", err),
		)

		return
	} else if ok {
		c.AcceptClient(logger, state.ClientIdentifier{CID: client.CID, KID: client.KID}, client.CommonName)

		return
	}

	// Start the authentication process for the client.
	if err := c.startClientAuth(ctx, logger, client); err != nil {
		// Deny the client if an error occurred during the authentication process.
		logger.LogAttrs(ctx, slog.LevelError, "error starting client auth",
			slog.Any("err", err),
		)

		c.DenyClient(logger, state.ClientIdentifier{CID: client.CID, KID: client.KID}, "internal error")
	}
}

// startClientAuth initiates the authentication process for the client.
// The openvpn-auth-oauth2 plugin will send a client-pending-auth command to the OpenVPN management interface.
func (c *Client) startClientAuth(ctx context.Context, logger *slog.Logger, client connection.Client) error {
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

	logger.LogAttrs(ctx, slog.LevelInfo, "sent client-pending-auth command")

	_, err = c.SendCommandf(`client-pending-auth %d %d "WEB_AUTH::%s" %.0f`, client.CID, client.KID, startURL, c.conf.OpenVpn.AuthPendingTimeout.Seconds())
	if err != nil {
		return fmt.Errorf("error sending client-pending-auth command: %w", err)
	}

	return nil
}

func (c *Client) checkAuthBypass(client connection.Client) bool {
	return slices.Contains(c.conf.OpenVpn.Bypass.CommonNames, client.CommonName)
}

func (c *Client) silentReAuthentication(ctx context.Context, logger *slog.Logger, client connection.Client) (bool, error) {
	if !c.conf.OAuth2.Refresh.Enabled {
		logger.LogAttrs(ctx, slog.LevelDebug, "silent re-authentication disabled by configuration")

		return false, nil
	}

	if c.conf.OAuth2.Refresh.UseSessionID {
		if client.SessionID == "" || !slices.Contains([]string{"Initial", "AuthenticatedEmptyUser", "Authenticated"}, client.SessionState) {
			return false, ErrClientSessionStateInvalidOrExpired
		}
	} else if client.SessionID != "" {
		logger.LogAttrs(ctx, slog.LevelWarn, "detected client session ID but not configured to use it. Please enable --oauth2.refresh.use-session-id")
	}

	if c.oauth2 == nil {
		return false, errors.New("oauth2 client not set")
	}

	ok, err := c.oauth2.RefreshClientAuth(ctx, logger, client)
	if err != nil {
		logger.LogAttrs(ctx, slog.LevelWarn, "error refreshing client auth", slog.Any("err", err))
	}

	logger.LogAttrs(ctx, slog.LevelDebug, "silent re-authentication", slog.Bool("result", ok))

	return ok, nil
}

func (c *Client) clientEstablished(ctx context.Context, logger *slog.Logger, client connection.Client) {
	logger.LogAttrs(ctx, slog.LevelInfo, "client established",
		slog.String("vpn_ip", client.VPNAddress),
	)
}

func (c *Client) clientDisconnect(ctx context.Context, logger *slog.Logger, client connection.Client) {
	logger.LogAttrs(ctx, slog.LevelInfo, "client disconnected")

	c.oauth2.ClientDisconnect(ctx, logger, client)
}
