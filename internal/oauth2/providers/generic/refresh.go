package generic

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/log"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
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
	// OIDC spec says that nonce is optional for refresh tokens
	// https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens
	// This means that we have to retry the refresh without nonce if we get an error
	// However, trying to refresh session with same refresh token could lead into an error
	// because refresh token may have a one time use policy
	// see: https://github.com/zitadel/oidc/issues/509
	if errors.Is(err, oidc.ErrNonceInvalid) {
		ctx = context.WithValue(ctx, types.CtxNonce{}, "")
		newTokens, err = rp.RefreshTokens[*oidc.IDTokenClaims](ctx, relyingParty, refreshToken, "", "")
	}

	if err != nil {
		return "", fmt.Errorf("error from token exchange: %w", err)
	}

	return newTokens.RefreshToken, nil
}
