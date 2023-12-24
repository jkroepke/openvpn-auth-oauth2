package oauth2

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/log"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/storage"
	"github.com/zitadel/logging"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// RefreshClientAuth initiate a non-interactive authentication against the sso provider.
func (p *Provider) RefreshClientAuth(clientID uint64, logger *slog.Logger) (bool, error) {
	refreshToken, err := p.storage.Get(clientID)
	if err != nil {
		if errors.Is(err, storage.ErrNotExists) {
			return false, nil
		}

		return false, fmt.Errorf("error from token store: %w", err)
	}

	logger.Info("initiate non-interactive authentication via refresh token")
	ctx := logging.ToContext(context.Background(), log.NewZitadelLogger(logger))

	newTokens, err := rp.RefreshTokens[*oidc.IDTokenClaims](ctx, p.RelyingParty, refreshToken, "", "")
	if err != nil {
		return false, fmt.Errorf("failed authentication via refresh token %w", err)
	}

	logger.Info("successful authenticate via refresh token")

	if err = p.storage.Set(clientID, newTokens.RefreshToken); err != nil {
		return true, fmt.Errorf("error from token store: %w", err)
	}

	return true, nil
}

// ClientDisconnect purges the refresh token from store.
func (p *Provider) ClientDisconnect(clientID uint64) {
	p.storage.Delete(clientID)
}
