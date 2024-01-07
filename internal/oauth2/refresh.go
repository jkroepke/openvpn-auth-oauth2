package oauth2

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/log"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/storage"
	"github.com/zitadel/logging"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
)

// RefreshClientAuth initiate a non-interactive authentication against the sso provider.
func (p *Provider) RefreshClientAuth(clientID uint64, logger *slog.Logger) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	refreshToken, err := p.storage.Get(clientID)
	if err != nil {
		if errors.Is(err, storage.ErrNotExists) {
			return false, nil
		}

		return false, fmt.Errorf("error from token store: %w", err)
	}

	if p.conf.OAuth2.Nonce {
		ctx = context.WithValue(ctx, types.CtxNonce{}, p.GetNonce(clientID))
	}

	logger.Info("initiate non-interactive authentication via refresh token")

	refreshToken, err = p.OIDC.Refresh(ctx, logger, refreshToken, p.RelyingParty)
	if err != nil {
		return false, fmt.Errorf("error from token exchange: %w", err)
	}

	logger.Info("successful authenticate via refresh token")

	if err = p.storage.Set(clientID, refreshToken); err != nil {
		return true, fmt.Errorf("error from token store: %w", err)
	}

	return true, nil
}

// ClientDisconnect purges the refresh token from the [storage.Storage].
func (p *Provider) ClientDisconnect(clientID uint64, logger *slog.Logger) {
	refreshToken, err := p.storage.Get(clientID)
	if err != nil {
		return
	}

	logger.Debug("revoke refresh token")

	ctx := logging.ToContext(context.Background(), log.NewZitadelLogger(logger))
	if err = rp.RevokeToken(ctx, p.RelyingParty, refreshToken, "refresh_token"); err != nil {
		if err.Error() != "RelyingParty does not support RevokeCaller" {
			logger.Warn("refresh token revoke error: " + err.Error())
		}
	}

	p.storage.Delete(clientID)
}
