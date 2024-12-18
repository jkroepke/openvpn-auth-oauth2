package oauth2

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn/connection"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/storage"
)

// RefreshClientAuth initiate a non-interactive authentication against the sso provider.
//
//nolint:cyclop
func (p *Provider) RefreshClientAuth(logger *slog.Logger, client connection.Client) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	id := strconv.FormatUint(client.CID, 10)
	if p.conf.OAuth2.Refresh.UseSessionID && client.SessionID != "" {
		id = client.SessionID
	}

	refreshToken, err := p.storage.Get(id)
	if err != nil {
		if errors.Is(err, storage.ErrNotExists) {
			return false, nil
		}

		return false, fmt.Errorf("error from token store: %w", err)
	} else if refreshToken == "" {
		logger.WarnContext(ctx, "stored refresh token is empty. This should not happen. Please report this issue.")

		return false, nil
	}

	if !p.conf.OAuth2.Refresh.ValidateUser {
		return true, nil
	}

	if p.conf.OAuth2.Nonce {
		ctx = context.WithValue(ctx, types.CtxNonce{}, p.GetNonce(id))
	}

	logger.Info("initiate non-interactive authentication via refresh token")

	tokens, err := p.Provider.Refresh(ctx, logger, p.RelyingParty, refreshToken)
	if err != nil {
		return false, fmt.Errorf("error from non-interactive authentication via refresh token: %w", err)
	}

	session := state.New(
		state.ClientIdentifier{CID: client.CID, KID: client.KID, SessionID: client.SessionID},
		client.IPAddr, client.IPPort, client.CommonName, client.SessionState,
	)

	user, err := p.Provider.GetUser(ctx, logger, tokens)
	if err != nil {
		return false, fmt.Errorf("error fetch user data: %w", err)
	}

	err = p.Provider.CheckUser(ctx, session, user, tokens)
	if err != nil {
		return false, fmt.Errorf("error check user data: %w", err)
	}

	logger.Info("successful authenticate via refresh token")

	refreshToken, err = p.Provider.GetRefreshToken(tokens)

	switch {
	case errors.Is(err, types.ErrNoRefreshToken):
		logMessage := logger.WarnContext
		if client.SessionState == "AuthenticatedEmptyUser" || client.SessionState == "Authenticated" {
			logMessage = logger.DebugContext
		}

		logMessage(ctx, fmt.Errorf("oauth2.refresh is enabled, but %w", err).Error())
	case err != nil:
		logger.WarnContext(ctx, fmt.Errorf("oauth2.refresh is enabled, but %w", err).Error())
	default:
		logger.DebugContext(ctx, "store new refresh token into token store")

		if err = p.storage.Set(id, refreshToken); err != nil {
			return true, fmt.Errorf("error from token store: %w", err)
		}
	}

	return true, nil
}

// ClientDisconnect purges the refresh token from the [storage.Storage].
func (p *Provider) ClientDisconnect(ctx context.Context, logger *slog.Logger, client connection.Client) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if p.conf.OAuth2.Refresh.UseSessionID {
		return
	}

	id := strconv.FormatUint(client.CID, 10)

	refreshToken, err := p.storage.Get(id)
	if err != nil {
		if errors.Is(err, storage.ErrNotExists) {
			logger.DebugContext(ctx, fmt.Errorf("error from token store: %w", err).Error())
		} else {
			logger.WarnContext(ctx, fmt.Errorf("error from token store: %w", err).Error())
		}

		return
	}

	p.storage.Delete(id)

	if !p.conf.OAuth2.Refresh.ValidateUser {
		return
	}

	logger.DebugContext(ctx, "revoke refresh token")

	if err = p.Provider.RevokeRefreshToken(ctx, logger, p.RelyingParty, refreshToken); err != nil {
		logger.WarnContext(ctx, err.Error())
	}
}
