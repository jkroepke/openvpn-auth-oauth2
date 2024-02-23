package generic

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/log"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/openvpn/connection"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/zitadel/logging"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func (p *Provider) GetRefreshToken(tokens *oidc.Tokens[*idtoken.Claims]) string {
	return tokens.RefreshToken
}

// Refresh initiates a non-interactive authentication against the sso provider.
func (p *Provider) Refresh(
	ctx context.Context, logger *slog.Logger, client connection.Client, refreshToken string, relyingParty rp.RelyingParty,
) (string, error) {
	ctx = logging.ToContext(ctx, log.NewZitadelLogger(logger))

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
		return "", fmt.Errorf("error from token exchange: %w", err)
	}

	session := state.New(state.ClientIdentifier{CID: client.CID, KID: client.KID}, client.IPAddr, client.CommonName)

	user, err := p.GetUser(ctx, tokens)
	if err != nil {
		return "", fmt.Errorf("error fetch user data: %w", err)
	}

	err = p.CheckUser(ctx, session, user, tokens)
	if err != nil {
		return "", fmt.Errorf("error check user data: %w", err)
	}

	return tokens.RefreshToken, nil
}
