package google

import (
	"context"
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func (p *Provider) GetRefreshToken(tokens *oidc.Tokens[*idtoken.Claims]) (string, error) {
	return p.Provider.GetRefreshToken(tokens) //nolint:wrapcheck
}

func (p *Provider) Refresh(ctx context.Context, logger *slog.Logger, relyingParty rp.RelyingParty, refreshToken string) (*oidc.Tokens[*idtoken.Claims], error) {
	return p.Provider.Refresh(ctx, logger, relyingParty, refreshToken) //nolint:wrapcheck
}

func (p *Provider) RevokeRefreshToken(ctx context.Context, logger *slog.Logger, relyingParty rp.RelyingParty, refreshToken string) error {
	return p.Provider.RevokeRefreshToken(ctx, logger, relyingParty, refreshToken) //nolint:wrapcheck
}
