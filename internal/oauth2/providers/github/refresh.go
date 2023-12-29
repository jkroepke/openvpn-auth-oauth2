package github

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

// GetRefreshToken returns the [oauth2.Token.AccessToken] of the user, since it does not expire.
// OAuth2 App on GitHub doesn't provide a refresh token.
func (p *Provider) GetRefreshToken(tokens *oidc.Tokens[*idtoken.Claims]) string {
	return tokens.AccessToken
}

// Refresh use the [oauth2.Token.AccessToken] from initial authentication and call the REST API if the user is still present
// inside the required groups.
func (p *Provider) Refresh(ctx context.Context, _ *slog.Logger, accessToken string, _ rp.RelyingParty) (string, error) {
	token := &oidc.Tokens[*idtoken.Claims]{
		Token:         &oauth2.Token{AccessToken: accessToken},
		IDTokenClaims: &idtoken.Claims{},
	}

	user, err := p.GetUser(ctx, token)
	if err != nil {
		return "", fmt.Errorf("error fetch user data: %w", err)
	}

	err = p.CheckUser(ctx, state.State{}, user, token)
	if err != nil {
		return "", fmt.Errorf("error check user data: %w", err)
	}

	return accessToken, nil
}
