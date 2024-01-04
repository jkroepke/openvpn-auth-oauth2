package generic

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/log"
	"github.com/zitadel/logging"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func (p *Provider) GetRefreshToken(tokens *oidc.Tokens[*idtoken.Claims]) string {
	return tokens.RefreshToken
}

// Refresh initiates a non-interactive authentication against the sso provider.
func (p *Provider) Refresh(ctx context.Context, logger *slog.Logger, refreshToken string, relyingParty rp.RelyingParty) (string, error) {
	ctx = logging.ToContext(ctx, log.NewZitadelLogger(logger))

	newTokens, err := rp.RefreshTokens[*oidc.IDTokenClaims](ctx, relyingParty, refreshToken, "", "")
	if err != nil {
		return "", fmt.Errorf("error from token exchange: %w", err)
	}

	return newTokens.RefreshToken, nil
}
