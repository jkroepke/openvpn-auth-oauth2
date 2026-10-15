package oauth2

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/openvpn/connection"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/sessionregistry"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/state"
)

// SetSessionRegistry replaces the session registry. The daemon passes one
// registry that outlives configuration reloads.
func (c *Client) SetSessionRegistry(sessions *sessionregistry.Registry) {
	c.sessions = sessions
}

// RegisterClient records an accepted client and its OIDC identity in the
// session registry. A client without identity is not recorded, because no
// security event can match it. Without a registry, RegisterClient does nothing.
func (c *Client) RegisterClient(
	ctx context.Context, logger *slog.Logger, client state.ClientIdentifier, username string, identity sessionregistry.Identity,
) {
	if c.sessions == nil {
		return
	}

	if identity.IsZero() {
		logger.LogAttrs(ctx, slog.LevelDebug, "client has no OIDC identity; not adding it to the session registry")

		return
	}

	c.sessions.Add(sessionregistry.Entry{
		AuthenticatedAt:  time.Now(),
		Identity:         identity,
		OpenVPNSessionID: client.SessionID,
		Username:         username,
		CID:              client.CID,
	})
}

// RevokeRefreshState deletes the stored refresh state of a session registry
// entry, so the session cannot resume without an interactive login. With
// oauth2.refresh.validate-user, the refresh token is also revoked at the
// provider.
func (c *Client) RevokeRefreshState(ctx context.Context, logger *slog.Logger, entry sessionregistry.Entry) error {
	if !c.conf.OAuth2.Refresh.Enabled {
		return nil
	}

	if c.conf.OAuth2.Refresh.UseSessionID && entry.OpenVPNSessionID != "" {
		return c.deleteRefreshToken(ctx, logger, entry.OpenVPNSessionID)
	}

	if !entry.Connected {
		return errors.New("dormant session registry entry has no OpenVPN session ID")
	}

	return c.deleteRefreshToken(ctx, logger, strconv.FormatUint(entry.CID, 10))
}

// unregisterClient removes a disconnected client from the session registry.
// With oauth2.refresh.use-session-id, the session can reconnect without an
// interactive login until its refresh state expires, so the registry keeps
// it as long.
func (c *Client) unregisterClient(ctx context.Context, logger *slog.Logger, client connection.Client) {
	if c.sessions == nil {
		return
	}

	var retain time.Duration
	if c.conf.OAuth2.Refresh.Enabled && c.conf.OAuth2.Refresh.UseSessionID {
		retain = c.conf.OAuth2.Refresh.Expires
	}

	if _, ok := c.sessions.Disconnect(client.CID, retain); ok {
		logger.LogAttrs(ctx, slog.LevelDebug, "client removed from the session registry")
	}
}

// identityFromTokens returns the OIDC identity from the ID token claims,
// with the email from user when the ID token has none.
func identityFromTokens(tokens *idtoken.IDToken, user types.UserInfo) sessionregistry.Identity {
	identity := sessionregistry.Identity{Email: user.Email}

	if tokens == nil || tokens.IDTokenClaims == nil {
		return identity
	}

	claims := tokens.IDTokenClaims
	identity.Issuer = claims.Issuer
	identity.Subject = claims.Subject

	if claims.EMail != "" {
		identity.Email = claims.EMail
	}

	if sid, ok := claims.Claims["sid"].(string); ok {
		identity.SessionID = sid
	}

	return identity
}
