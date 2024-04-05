package google

import (
	"context"
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func (p *Provider) GetRefreshToken(tokens *oidc.Tokens[*idtoken.Claims]) string {
	return p.Provider.GetRefreshToken(tokens)
}

func (p *Provider) Refresh(ctx context.Context, logger *slog.Logger, refreshToken string) (*oidc.Tokens[*idtoken.Claims], error) {
	return p.Provider.Refresh(ctx, logger, refreshToken) //nolint:wrapcheck
}

func (p *Provider) EndSession(ctx context.Context, logger *slog.Logger, idToken string) error {
	return p.Provider.EndSession(ctx, logger, idToken) //nolint:wrapcheck
}

func (p *Provider) RevokeRefreshToken(ctx context.Context, logger *slog.Logger, refreshToken string) error {
	return p.Provider.RevokeRefreshToken(ctx, logger, refreshToken) //nolint:wrapcheck
}
