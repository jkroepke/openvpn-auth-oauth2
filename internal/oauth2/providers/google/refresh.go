package google

import (
	"context"
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func (p *Provider) GetRefreshToken(tokens *oidc.Tokens[*idtoken.Claims]) string {
	return p.Provider.GetRefreshToken(tokens)
}

func (p *Provider) Refresh(ctx context.Context, logger *slog.Logger, refreshToken string, relyingParty rp.RelyingParty) (*oidc.Tokens[*idtoken.Claims], error) {
	return p.Provider.Refresh(ctx, logger, refreshToken, relyingParty) //nolint:wrapcheck
}
