package oauth2

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn/connection"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/tokenstorage"
)

// RefreshClientAuth initiate a non-interactive authentication against the sso provider.
//
//nolint:cyclop
func (c Client) RefreshClientAuth(ctx context.Context, logger *slog.Logger, client connection.Client) (bool, error) {
	clientID := strconv.FormatUint(client.CID, 10)
	if c.conf.OAuth2.Refresh.UseSessionID && client.SessionID != "" {
		clientID = client.SessionID
	}

	refreshToken, err := c.storage.Get(clientID)
	if err != nil {
		if errors.Is(err, tokenstorage.ErrNotExists) {
			logger.LogAttrs(ctx, slog.LevelDebug, "no refresh token found for client "+clientID)

			return false, nil
		}

		return false, fmt.Errorf("error from token store: %w", err)
	} else if refreshToken == "" {
		logger.LogAttrs(ctx, slog.LevelWarn, "stored refresh token is empty. This should not happen. Please report this issue.")

		return false, nil
	}

	if !c.conf.OAuth2.Refresh.ValidateUser {
		logger.LogAttrs(ctx, slog.LevelInfo, "successful non-interactive authentication via internal token")

		return true, nil
	}

	if c.conf.OAuth2.Nonce {
		ctx = context.WithValue(ctx, types.CtxNonce{}, c.getNonce(clientID))
	}

	logger.LogAttrs(ctx, slog.LevelInfo, "initiate non-interactive authentication via refresh token")

	tokens, err := c.provider.Refresh(ctx, logger, c.relyingParty, refreshToken)
	if err != nil {
		return false, fmt.Errorf("error from non-interactive authentication via refresh token: %w", err)
	}

	session := state.New(
		state.ClientIdentifier{CID: client.CID, KID: client.KID, SessionID: client.SessionID},
		client.IPAddr, client.IPPort, client.CommonName, client.SessionState,
	)

	user, err := c.provider.GetUser(ctx, logger, tokens)
	if err != nil {
		return false, fmt.Errorf("error fetch user data: %w", err)
	}

	if err := c.provider.CheckUser(ctx, session, user, tokens); err != nil {
		return false, fmt.Errorf("error check user data: %w", err)
	}

	logger.LogAttrs(ctx, slog.LevelInfo, "successful authenticate via refresh token")

	refreshToken, err = c.provider.GetRefreshToken(tokens)
	if err != nil {
		logLevel := slog.LevelWarn

		if errors.Is(err, ErrNoRefreshToken) {
			if session.SessionState == "AuthenticatedEmptyUser" || session.SessionState == "Authenticated" {
				logLevel = slog.LevelDebug
			}
		}

		logger.LogAttrs(ctx, logLevel, fmt.Errorf("oauth2.refresh is enabled, but %w", err).Error())

		return true, nil
	}

	if refreshToken == "" {
		logger.LogAttrs(ctx, slog.LevelWarn, "refresh token is empty")
	} else if err = c.storage.Set(clientID, refreshToken); err != nil {
		logger.LogAttrs(ctx, slog.LevelWarn, "unable to store refresh token",
			slog.Any("err", err),
		)
	}

	return true, nil
}

// ClientDisconnect purges the refresh token from the [tokenstorage.Storage].
func (c Client) ClientDisconnect(ctx context.Context, logger *slog.Logger, client connection.Client) {
	if c.conf.OAuth2.Refresh.UseSessionID {
		return
	}

	id := strconv.FormatUint(client.CID, 10)

	refreshToken, err := c.storage.Get(id)
	if err != nil {
		logLevel := slog.LevelWarn
		if errors.Is(err, tokenstorage.ErrNotExists) {
			logLevel = slog.LevelDebug
		}

		logger.LogAttrs(ctx, logLevel, fmt.Errorf("error from token store: %w", err).Error())

		return
	}

	c.storage.Delete(id)

	if !c.conf.OAuth2.Refresh.ValidateUser {
		return
	}

	logger.LogAttrs(ctx, slog.LevelDebug, "revoke refresh token")

	if err = c.provider.RevokeRefreshToken(ctx, logger, c.relyingParty, refreshToken); err != nil {
		logger.LogAttrs(ctx, slog.LevelWarn, err.Error())
	}
}
