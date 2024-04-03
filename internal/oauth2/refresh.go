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
	"github.com/zitadel/logging"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
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
	}

	if !p.conf.OAuth2.Refresh.ValidateUser {
		return true, nil
	}

	if p.conf.OAuth2.Nonce {
		ctx = context.WithValue(ctx, types.CtxNonce{}, p.GetNonce(id))
	}

	logger.Info("initiate non-interactive authentication via refresh token")

	tokens, err := p.OIDC.Refresh(ctx, logger, refreshToken, p.RelyingParty)
	if err != nil {
		return false, fmt.Errorf("error from token exchange: %w", err)
	}

	session := state.New(state.ClientIdentifier{CID: client.CID, KID: client.KID}, client.IPAddr, client.IPPort, client.CommonName)

	user, err := p.OIDC.GetUser(ctx, logger, tokens)
	if err != nil {
		return false, fmt.Errorf("error fetch user data: %w", err)
	}

	err = p.OIDC.CheckUser(ctx, session, user, tokens)
	if err != nil {
		return false, fmt.Errorf("error check user data: %w", err)
	}

	logger.Info("successful authenticate via refresh token")

	if err = p.storage.Set(id, refreshToken); err != nil {
		return true, fmt.Errorf("error from token store: %w", err)
	}

	return true, nil
}

// ClientDisconnect purges the refresh token from the [storage.Storage].
func (p *Provider) ClientDisconnect(ctx context.Context, logger *slog.Logger, client connection.Client) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if p.conf.OAuth2.Refresh.UseSessionID || p.conf.OAuth2.Refresh.ValidateUser == false {
		return
	}

	id := strconv.FormatUint(client.CID, 10)

	refreshToken, err := p.storage.Get(id)
	if err != nil {
		logger.Warn(fmt.Errorf("error from token store: %w", err).Error())
		return
	}

	p.storage.Delete(id)

	tokens, err := p.OIDC.Refresh(ctx, logger, refreshToken, p.RelyingParty)
	if err != nil {
		logger.Warn(fmt.Errorf("error from token exchange: %w", err).Error())
	} else if tokens.IDToken != "" {
		_, err = rp.EndSession(ctx, p.RelyingParty, tokens.IDToken, "", "")
		if err != nil {
			logger.Warn(fmt.Errorf("error end session: %w", err).Error())
		}
	}

	logger.Debug("revoke refresh token")
	ctx = logging.ToContext(ctx, logger)
	if err = rp.RevokeToken(ctx, p.RelyingParty, refreshToken, "refresh_token"); err != nil {
		if !errors.Is(err, rp.ErrRelyingPartyNotSupportRevokeCaller) {
			logger.Warn(fmt.Errorf("refresh token revoke error: %w", err).Error())
		}
	}

	return
}
