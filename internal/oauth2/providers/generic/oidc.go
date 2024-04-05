package generic

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/zitadel/logging"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func (p *Provider) GetRefreshToken(tokens *oidc.Tokens[*idtoken.Claims]) string {
	return tokens.RefreshToken
}

// Refresh initiates a non-interactive authentication against the sso provider.
func (p *Provider) Refresh(ctx context.Context, logger *slog.Logger, relyingParty rp.RelyingParty, refreshToken string) (*oidc.Tokens[*idtoken.Claims], error) {
	ctx = logging.ToContext(ctx, logger)

	tokens, err := rp.RefreshTokens[*idtoken.Claims](ctx, relyingParty, refreshToken, "", "")
	// OIDC spec says that nonce is optional for refresh tokens
	// https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens
	// This means that we have to retry the refresh without a nonce if we get an error,
	// However, trying to refresh session with the same refresh token could lead into an error
	// because refresh token may have a one time use policy
	// see: https://github.com/zitadel/oidc/issues/509
	if errors.Is(err, oidc.ErrNonceInvalid) {
		ctx = context.WithValue(ctx, types.CtxNonce{}, "")
		tokens, err = rp.RefreshTokens[*idtoken.Claims](ctx, relyingParty, refreshToken, "", "")
	}

	if err != nil {
		return nil, fmt.Errorf("error from token exchange: %w", err)
	}

	return tokens, nil
}

func (p *Provider) EndSession(ctx context.Context, logger *slog.Logger, relyingParty rp.RelyingParty, idToken string) error {
	ctx = logging.ToContext(ctx, logger)

	_, err := rp.EndSession(ctx, relyingParty, idToken, "", "")
	if err != nil {
		return fmt.Errorf("error from end session: %w", err)
	}

	return nil
}

func (p *Provider) RevokeRefreshToken(ctx context.Context, logger *slog.Logger, relyingParty rp.RelyingParty, refreshToken string) error {
	ctx = logging.ToContext(ctx, logger)

	err := rp.RevokeToken(ctx, relyingParty, refreshToken, "refresh_token")
	if err != nil && !errors.Is(err, rp.ErrRelyingPartyNotSupportRevokeCaller) {
		return fmt.Errorf("error from revoke token: %w", err)
	}

	return nil
}
