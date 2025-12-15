package github

import (
	"context"
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	gooauth2 "golang.org/x/oauth2"
)

func (p Provider) GetToken(tokens idtoken.IDToken) (string, error) {
	if tokens == nil {
		return "", oauth2.ErrMissingToken
	}

	return tokens.AccessToken, nil
}

// GetRefreshToken returns the [oauth2.Token.AccessToken] of the user, since it does not expire.
// OAuth2 App on GitHub doesn't provide a refresh token.
func (p Provider) GetRefreshToken(tokens idtoken.IDToken) (string, error) {
	if tokens == nil {
		return "", oauth2.ErrMissingToken
	}

	return tokens.AccessToken, nil
}

// Refresh use the [oauth2.Token.AccessToken] from initial authentication and call the REST API if the user is still present
// inside the required groups.
func (p Provider) Refresh(_ context.Context, _ *slog.Logger, _ rp.RelyingParty, refreshToken string) (idtoken.IDToken, error) {
	return &oidc.Tokens[*idtoken.Claims]{
		Token:         &gooauth2.Token{AccessToken: refreshToken},
		IDTokenClaims: &idtoken.Claims{},
	}, nil
}

func (p Provider) RevokeRefreshToken(_ context.Context, _ *slog.Logger, _ rp.RelyingParty, _ string) error {
	// GitHub doesn't support revoke token
	return nil
}
