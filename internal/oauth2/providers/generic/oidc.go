package generic

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/zitadel/logging"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func (p Provider) GetToken(tokens idtoken.IDToken) (string, error) {
	if tokens == nil {
		return "", oauth2.ErrMissingToken
	}

	switch {
	case tokens.IDToken != "":
		return tokens.IDToken, nil
	case tokens.AccessToken != "":
		return tokens.AccessToken, nil
	default:
		return "", oauth2.ErrMissingToken
	}
}

func (p Provider) GetRefreshToken(tokens idtoken.IDToken) (string, error) {
	if tokens == nil {
		return "", oauth2.ErrMissingToken
	}

	if tokens.RefreshToken == "" {
		return "", oauth2.ErrNoRefreshToken
	}

	return tokens.RefreshToken, nil
}

// Refresh initiates a non-interactive authentication against the sso provider.
func (p Provider) Refresh(ctx context.Context, logger *slog.Logger, relyingParty rp.RelyingParty, refreshToken string) (idtoken.IDToken, error) {
	ctx = logging.ToContext(ctx, logger)

	// Apply refresh nonce control based on configuration
	switch p.Conf.OAuth2.RefreshNonce {
	case config.OAuth2RefreshNonceEmpty:
		// Always use empty nonce for refresh requests
		ctx = context.WithValue(ctx, types.CtxNonce{}, "")
	case config.OAuth2RefreshNonceEqual:
		// Use the same nonce as initial authentication (default behavior)
		// No additional action needed - relies on the nonce set by calling code
	case config.OAuth2RefreshNonceAuto:
		// Fallback to original behavior: try with nonce, retry without on error
	}

	tokens, err := rp.RefreshTokens[*idtoken.Claims](ctx, relyingParty, refreshToken, "", "")

	// Only retry for auto mode when we get a nonce error
	if p.Conf.OAuth2.RefreshNonce == config.OAuth2RefreshNonceAuto && errors.Is(err, oidc.ErrNonceInvalid) {
		// OIDC spec says that nonce is optional for refresh tokens
		// https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens
		// This means that we have to retry the refresh without a nonce if we get an error,
		// However, trying to refresh session with the same refresh token could lead into an error
		// because refresh token may have a one time use policy
		// see: https://github.com/zitadel/oidc/issues/509
		ctx = context.WithValue(ctx, types.CtxNonce{}, "")
		tokens, err = rp.RefreshTokens[*idtoken.Claims](ctx, relyingParty, refreshToken, "", "")
	}

	if err != nil {
		return nil, fmt.Errorf("error from token exchange via refresh token: %w", err)
	}

	return tokens, nil
}

func (p Provider) RevokeRefreshToken(ctx context.Context, logger *slog.Logger, relyingParty rp.RelyingParty, refreshToken string) error {
	ctx = logging.ToContext(ctx, logger)

	err := rp.RevokeToken(ctx, relyingParty, refreshToken, "refresh_token")
	if err != nil && !errors.Is(err, rp.ErrRelyingPartyNotSupportRevokeCaller) {
		return fmt.Errorf("error revoke refresh token: %w", err)
	}

	return nil
}
