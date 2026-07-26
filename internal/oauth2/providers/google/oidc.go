package google

import (
	"context"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
)

// GetRefreshToken delegates refresh token extraction to the embedded generic provider.
func (p Provider) GetRefreshToken(tokens *idtoken.IDToken) (string, error) {
	return p.Provider.GetRefreshToken(tokens) //nolint:wrapcheck
}

// Refresh delegates refresh-token authentication to the embedded generic provider.
func (p Provider) Refresh(ctx context.Context, relyingParty rp.RelyingParty, refreshToken string) (*idtoken.IDToken, error) {
	return p.Provider.Refresh(ctx, relyingParty, refreshToken) //nolint:wrapcheck
}

// RevokeRefreshToken delegates refresh token revocation to the embedded generic provider.
func (p Provider) RevokeRefreshToken(ctx context.Context, relyingParty rp.RelyingParty, refreshToken string) error {
	return p.Provider.RevokeRefreshToken(ctx, relyingParty, refreshToken) //nolint:wrapcheck
}
