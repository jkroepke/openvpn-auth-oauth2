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
func (p *Provider) RefreshClientAuth(id string, logger *slog.Logger) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	refreshToken, err := p.storage.Get(id)
	if err != nil {
		if errors.Is(err, storage.ErrNotExists) {
			return false, nil
		}

		return false, fmt.Errorf("error from token store: %w", err)
	}

	if p.conf.OAuth2.Nonce {
		ctx = context.WithValue(ctx, types.CtxNonce{}, p.GetNonce(id))
	}

	logger.Info("initiate non-interactive authentication via refresh token")

	refreshToken, err = p.OIDC.Refresh(ctx, logger, refreshToken, p.RelyingParty)
	if err != nil {
		return false, fmt.Errorf("error from token exchange: %w", err)
	}

	logger.Info("successful authenticate via refresh token")

	if err = p.storage.Set(id, refreshToken); err != nil {
		return true, fmt.Errorf("error from token store: %w", err)
	}

	return true, nil
}

// ClientDisconnect purges the refresh token from the [storage.Storage].
func (p *Provider) ClientDisconnect(id string, logger *slog.Logger) {
	if p.conf.OAuth2.Refresh.UseSessionID {
		return
	}

	refreshToken, err := p.storage.Get(id)
	if err != nil {
		return
	}

	logger.Debug("revoke refresh token")

	ctx := logging.ToContext(context.Background(), log.NewZitadelLogger(logger))
	if err = rp.RevokeToken(ctx, p.RelyingParty, refreshToken, "refresh_token"); err != nil {
		if !errors.Is(err, rp.ErrRelyingPartyNotSupportRevokeCaller) {
			logger.Warn("refresh token revoke error: " + err.Error())
		}
	}

	p.storage.Delete(id)
}
