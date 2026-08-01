package openvpn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/openvpn/connection"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/state"
)

const openVPNManagementCommandBodyLimit = 1023

func (c *Client) processClient(ctx context.Context, client connection.Client) error {
	logger := slog.New(c.logger.Handler().WithAttrs([]slog.Attr{
		slog.String("ip", client.IPAddr+":"+client.IPPort),
		slog.Uint64("cid", client.CID),
		slog.Uint64("kid", client.KID),
		slog.String("common_name", client.CommonName),
		slog.String("reason", client.Reason),
		slog.String("session_id", client.SessionID),
		slog.String("session_state", client.SessionState),
	}))

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	switch client.Reason {
	case "REAUTH":
		if !c.conf.OpenVPN.ReAuthentication {
			logger.LogAttrs(ctx, slog.LevelInfo, "client re-authentication not enabled")
			c.DenyClient(ctx, logger, state.ClientIdentifier{CID: client.CID, KID: client.KID}, "client re-authentication not enabled")

			return nil
		}

		fallthrough
	case "CONNECT":
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
		c.acceptBypassedClient(ctx, logger, client)

		return
	}

	// Check if the client supports SSO authentication via webauth.
	if !c.checkClientSsoCapabilities(client) {
		errorSsoNotSupported := "OpenVPN Client does not support SSO authentication via webauth"
		logger.LogAttrs(ctx, slog.LevelWarn, errorSsoNotSupported)
		c.DenyClient(ctx, logger, state.ClientIdentifier{CID: client.CID, KID: client.KID}, errorSsoNotSupported)

		return
	}

	// Check if the client is already authenticated and refresh the client's authentication if enabled.
	// If the client is successfully re-authenticated, accept the client.
	user, tokens, clientConfigNames, ok, err := c.silentReAuthentication(ctx, logger, client)
	if err != nil {
		c.DenyClient(ctx, logger, state.ClientIdentifier{CID: client.CID, KID: client.KID}, ReasonStateExpiredOrInvalid)

		logger.LogAttrs(
			ctx, slog.LevelError, "error refreshing client auth",
			slog.Any("err", err),
		)

		return
	}

	if ok {
		c.acceptSilentlyReAuthenticatedClient(ctx, logger, client, user, tokens, clientConfigNames)

		return
	}

	// Start the authentication process for the client.
	if err := c.startClientAuth(ctx, logger, client); err != nil {
		// Deny the client if an error occurred during the authentication process.
		logger.LogAttrs(
			ctx, slog.LevelError, "error starting client auth",
			slog.Any("err", err),
		)

		c.DenyClient(ctx, logger, state.ClientIdentifier{CID: client.CID, KID: client.KID}, "internal error")
	}
}

func (c *Client) acceptBypassedClient(ctx context.Context, logger *slog.Logger, client connection.Client) {
	logger.LogAttrs(ctx, slog.LevelInfo, "client bypass authentication")

	clientIdentifier := stateClientIdentifier(client)
	if err := c.AcceptClient(ctx, logger, clientIdentifier, client.CommonName, ""); err != nil {
		logger.LogAttrs(ctx, slog.LevelWarn, "failed to accept bypassed client", slog.Any("err", err))
		c.DenyClient(ctx, logger, clientIdentifier, "authentication acceptance failed")
	}
}

func (c *Client) acceptSilentlyReAuthenticatedClient(
	ctx context.Context,
	logger *slog.Logger,
	client connection.Client,
	user types.UserInfo,
	tokens *idtoken.IDToken,
	clientConfigNames []string,
) {
	if tokens != nil && len(clientConfigNames) == 0 {
		var err error

		clientConfigNames, err = c.oauth2.ResolveClientConfigNames(
			types.AuthModeNonInteractive,
			state.State{
				Client:       stateClientIdentifier(client),
				IPAddr:       client.IPAddr,
				IPPort:       client.IPPort,
				SessionState: client.SessionState,
			},
			tokens,
			user,
		)
		if err != nil {
			logger.LogAttrs(ctx, slog.LevelWarn, "failed to resolve client config", slog.Any("err", err))
			c.DenyClient(ctx, logger, stateClientIdentifier(client), "invalid client config")

			return
		}
	}

	clientIdentifier := stateClientIdentifier(client)
	if err := c.AcceptClient(ctx, logger, clientIdentifier, user.Username, clientConfigNames...); err != nil {
		logger.LogAttrs(ctx, slog.LevelWarn, "failed to accept silently re-authenticated client", slog.Any("err", err))
		c.DenyClient(ctx, logger, clientIdentifier, "authentication acceptance failed")
	}
}

func stateClientIdentifier(client connection.Client) state.ClientIdentifier {
	return state.ClientIdentifier{
		SessionID:         client.SessionID,
		CommonName:        client.CommonName,
		CID:               client.CID,
		KID:               client.KID,
		UsernameIsDefined: client.UsernameIsDefined,
	}
}

// startClientAuth initiates the authentication process for the client.
// The openvpn-auth-oauth2 plugin will send a client-pending-auth command to the OpenVPN management interface.
func (c *Client) startClientAuth(ctx context.Context, logger *slog.Logger, client connection.Client) error {
	clientIdentifier := state.ClientIdentifier{
		CID:        client.CID,
		KID:        client.KID,
		CommonName: client.CommonName,
	}

	if c.conf.OAuth2.Refresh.UseSessionID {
		clientIdentifier.SessionID = client.SessionID
	}

	var (
		ipAddr string
		ipPort string
	)

	if c.conf.Log.VPNClientIP || c.conf.HTTP.Check.IPAddr || c.conf.OAuth2.Validate.Expression != "" {
		ipAddr = client.IPAddr
	}

	if c.conf.Log.VPNClientIP {
		ipPort = client.IPPort
	}

	encryptedOIDCState, err := c.oauth2.EncryptState(state.State{
		Client:       clientIdentifier,
		IPAddr:       ipAddr,
		IPPort:       ipPort,
		SessionState: client.SessionState,
	})
	if err != nil {
		return fmt.Errorf("error encoding state: %w", err)
	}

	startURL := buildOAuth2StartURL(c.conf.HTTP.BaseURL.String(), encryptedOIDCState)

	command, err := buildClientPendingAuthCommand(client, startURL, c.conf.OpenVPN.AuthPendingTimeout)
	if err != nil {
		return err
	}

	logger.LogAttrs(ctx, slog.LevelInfo, "sent client-pending-auth command")

	_, err = c.SendCommand(ctx, command, false)
	if err != nil {
		return fmt.Errorf("error sending client-pending-auth command: %w", err)
	}

	return nil
}

func buildOAuth2StartURL(baseURL string, encryptedOIDCState state.EncryptedState) string {
	return strings.TrimSuffix(baseURL, "/") + "/oauth2/start?state=" + encryptedOIDCState
}

func buildClientPendingAuthCommand(client connection.Client, startURL string, timeout time.Duration) (string, error) {
	const (
		commandPrefix = "client-pending-auth "
		webAuthPrefix = ` "WEB_AUTH::`
		commandSuffix = `" `
	)

	// Keep the numeric fields in stack-backed scratch buffers so building a valid
	// command requires only the returned string's allocation.
	var (
		cidBuffer     [20]byte
		kidBuffer     [20]byte
		timeoutBuffer [20]byte
	)

	cid := strconv.AppendUint(cidBuffer[:0], client.CID, 10)
	kid := strconv.AppendUint(kidBuffer[:0], client.KID, 10)
	timeoutSeconds := strconv.AppendFloat(timeoutBuffer[:0], timeout.Seconds(), 'f', 0, 64)
	commandSize := len(commandPrefix) + len(cid) + 1 + len(kid) + len(webAuthPrefix) +
		len(startURL) + len(commandSuffix) + len(timeoutSeconds)

	if commandSize > openVPNManagementCommandBodyLimit {
		return "", fmt.Errorf(
			"client-pending-auth command is %d bytes; OpenVPN accepts at most %d bytes",
			commandSize,
			openVPNManagementCommandBodyLimit,
		)
	}

	var command strings.Builder
	command.Grow(commandSize)
	command.WriteString(commandPrefix)
	_, _ = command.Write(cid)
	_ = command.WriteByte(' ')
	_, _ = command.Write(kid)
	command.WriteString(webAuthPrefix)
	command.WriteString(startURL)
	command.WriteString(commandSuffix)
	_, _ = command.Write(timeoutSeconds)

	return command.String(), nil
}

// checkAuthBypass checks if the client is allowed to bypass authentication based on its common name.
// It returns true if the client is allowed to bypass authentication, false otherwise.
func (c *Client) checkAuthBypass(client connection.Client) bool {
	for _, pattern := range c.conf.OpenVPN.Bypass.CommonNames {
		if pattern.MatchString(client.CommonName) {
			return true
		}
	}

	return false
}

// silentReAuthentication attempts to silently re-authenticate the client using a refresh token if available.
// It returns true if the client was successfully re-authenticated, false otherwise.
func (c *Client) silentReAuthentication(
	ctx context.Context, logger *slog.Logger, client connection.Client,
) (types.UserInfo, *idtoken.IDToken, []string, bool, error) {
	if !c.conf.OAuth2.Refresh.Enabled {
		logger.LogAttrs(ctx, slog.LevelDebug, "silent re-authentication disabled by configuration")

		return types.UserInfo{}, nil, nil, false, nil
	}

	if c.conf.OAuth2.Refresh.UseSessionID {
		if client.SessionID == "" || !slices.Contains([]string{"Initial", "AuthenticatedEmptyUser", "Authenticated"}, client.SessionState) {
			return types.UserInfo{}, nil, nil, false, ErrClientSessionStateInvalidOrExpired
		}
	} else if client.SessionID != "" {
		logger.LogAttrs(ctx, slog.LevelWarn, "detected client session ID but not configured to use it. Please enable --oauth2.refresh.use-session-id")
	}

	if c.oauth2 == nil {
		return types.UserInfo{}, nil, nil, false, errors.New("oauth2 client not set")
	}

	user, token, clientConfigNames, ok, err := c.oauth2.RefreshClientAuth(ctx, logger, client)
	if err != nil {
		logger.LogAttrs(ctx, slog.LevelWarn, "error refreshing client auth", slog.Any("err", err))
	}

	logger.LogAttrs(ctx, slog.LevelDebug, "silent re-authentication", slog.Bool("result", ok))

	return user, token, clientConfigNames, ok, nil
}

func (c *Client) clientEstablished(ctx context.Context, logger *slog.Logger, client connection.Client) {
	logger.LogAttrs(
		ctx, slog.LevelInfo, "client established",
		slog.String("vpn_ip", client.VPNAddress),
	)
}

func (c *Client) clientDisconnect(ctx context.Context, logger *slog.Logger, client connection.Client) {
	logger.LogAttrs(ctx, slog.LevelInfo, "client disconnected")

	c.oauth2.ClientDisconnect(ctx, logger, client)
}
