package authentik

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/zitadel/logging"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
)

// GetRefreshToken returns the refresh token from the provided tokens.
func (p Provider) GetRefreshToken(tokens idtoken.IDToken) (string, error) {
	return p.Provider.GetRefreshToken(tokens) //nolint:wrapcheck
}

// Refresh initiates a non-interactive authentication against the Authentik OIDC provider.
func (p Provider) Refresh(ctx context.Context, logger *slog.Logger, relyingParty rp.RelyingParty, refreshToken string) (idtoken.IDToken, error) {
	ctx = logging.ToContext(ctx, logger)

	// Clear nonce for refresh requests
	ctx = context.WithValue(ctx, types.CtxNonce{}, "")

	tokens, err := rp.RefreshTokens[*idtoken.Claims](ctx, relyingParty, refreshToken, "", "")
	if err != nil {
		return nil, fmt.Errorf("error from token exchange via refresh token: %w", err)
	}

	return tokens, nil
}

// RevokeRefreshToken revokes the given refresh token.
func (p Provider) RevokeRefreshToken(ctx context.Context, logger *slog.Logger, relyingParty rp.RelyingParty, refreshToken string) error {
	return p.Provider.RevokeRefreshToken(ctx, logger, relyingParty, refreshToken) //nolint:wrapcheck
}