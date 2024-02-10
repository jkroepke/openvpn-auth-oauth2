package google

import (
	"context"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func (p *Provider) GetUser(ctx context.Context, tokens *oidc.Tokens[*idtoken.Claims]) (types.UserData, error) {
	return p.Provider.GetUser(ctx, tokens) //nolint:wrapcheck
}
