package generic

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/types"
	"github.com/zitadel/oidc/v3/pkg/client"
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
func (p Provider) Refresh(ctx context.Context, relyingParty rp.RelyingParty, refreshToken string) (*idtoken.IDToken, error) {
	// Apply refresh nonce control based on configuration
	if p.Conf.OAuth2.RefreshNonce == config.OAuth2RefreshNonceEmpty {
		ctx = context.WithValue(ctx, types.CtxNonce{}, "")
	}

	tokens, err := refreshTokens(ctx, relyingParty, refreshToken)

	// Only retry for auto mode when we get a nonce error
	if p.Conf.OAuth2.RefreshNonce == config.OAuth2RefreshNonceAuto && errors.Is(err, oidc.ErrNonceInvalid) {
		// OIDC spec says that nonce is optional for refresh tokens
		// https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens
		// This means that we have to retry the refresh without a nonce if we get an error,
		// However, trying to refresh session with the same refresh token could lead into an error
		// because refresh token may have a one time use policy
		// see: https://github.com/zitadel/oidc/issues/509
		ctx = context.WithValue(ctx, types.CtxNonce{}, "")
		tokens, err = refreshTokens(ctx, relyingParty, refreshToken)
	}

	if err != nil {
		return nil, fmt.Errorf("error from token exchange via refresh token: %w", err)
	}

	return tokens, nil
}

// refreshTokens calls rp.RefreshTokens. With a private key configured
// (private_key_jwt), the client authenticates with a signed assertion; without
// one, rp.RefreshTokens falls back to client_id and client_secret, which is
// empty in that case. Each call signs a new assertion, since the assertion
// carries a jti that the provider may reject when it is reused.
func refreshTokens(ctx context.Context, relyingParty rp.RelyingParty, refreshToken string) (*idtoken.IDToken, error) {
	signer := relyingParty.Signer()
	if signer == nil {
		return rp.RefreshTokens[*idtoken.Claims](ctx, relyingParty, refreshToken, "", "")
	}

	assertion, err := client.SignedJWTProfileAssertion(
		relyingParty.OAuthConfig().ClientID, []string{relyingParty.Issuer()}, time.Hour, signer,
	)
	if err != nil {
		return nil, fmt.Errorf("error signing client assertion: %w", err)
	}

	return rp.RefreshTokens[*idtoken.Claims](ctx, relyingParty, refreshToken, assertion, oidc.ClientAssertionTypeJWTAssertion)
}

// RevokeRefreshToken revokes a refresh token when the relying party supports token revocation.
func (p Provider) RevokeRefreshToken(ctx context.Context, relyingParty rp.RelyingParty, refreshToken string) error {
	err := rp.RevokeToken(ctx, relyingParty, refreshToken, "refresh_token")
	if err != nil && !errors.Is(err, rp.ErrRelyingPartyNotSupportRevokeCaller) {
		return fmt.Errorf("error revoke refresh token: %w", err)
	}

	return nil
}
