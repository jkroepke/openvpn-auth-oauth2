package generic

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/zitadel/logging"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

// GetRefreshToken returns the provider refresh token from the OAuth2 token response.
func (p Provider) GetRefreshToken(tokens *idtoken.IDToken) (string, error) {
	if tokens == nil {
		return "", oauth2.ErrMissingToken
	}

	if tokens.RefreshToken == "" {
		return "", oauth2.ErrNoRefreshToken
	}

	return tokens.RefreshToken, nil
}

// Refresh initiates a non-interactive authentication against the sso provider.
func (p Provider) Refresh(ctx context.Context, logger *slog.Logger, relyingParty rp.RelyingParty, refreshToken string) (*idtoken.IDToken, error) {
	ctx = logging.ToContext(ctx, logger)

	// Apply refresh nonce control based on configuration
	if p.Conf.OAuth2.RefreshNonce == config.OAuth2RefreshNonceEmpty {
		ctx = context.WithValue(ctx, types.CtxNonce{}, "")
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

// RevokeRefreshToken revokes a refresh token when the relying party supports token revocation.
func (p Provider) RevokeRefreshToken(ctx context.Context, logger *slog.Logger, relyingParty rp.RelyingParty, refreshToken string) error {
	ctx = logging.ToContext(ctx, logger)

	err := rp.RevokeToken(ctx, revokeHTTPClientRelyingParty{RelyingParty: relyingParty}, refreshToken, "refresh_token")
	if err != nil && !errors.Is(err, rp.ErrRelyingPartyNotSupportRevokeCaller) {
		return fmt.Errorf("error revoke refresh token: %w", err)
	}

	return nil
}

type revokeHTTPClientRelyingParty struct {
	rp.RelyingParty
}

// HttpClient returns a shallow copy because upstream revoke mutates CheckRedirect.
//
//nolint:revive // HttpClient is required by the upstream rp.RelyingParty interface.
func (r revokeHTTPClientRelyingParty) HttpClient() *http.Client {
	client := r.RelyingParty.HttpClient()
	if client == nil {
		client = http.DefaultClient
	}

	return new(*client)
}
