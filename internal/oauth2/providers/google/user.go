package google

import (
	"context"
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func (p *Provider) GetUser(ctx context.Context, logger *slog.Logger, tokens *oidc.Tokens[*idtoken.Claims]) (types.UserData, error) {
	return p.Provider.GetUser(ctx, logger, tokens) //nolint:wrapcheck
}
