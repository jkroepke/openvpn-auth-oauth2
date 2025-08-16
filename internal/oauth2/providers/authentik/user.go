package authentik

import (
	"context"
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
)

// GetUser implements the [github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2.Provider] interface.
func (p Provider) GetUser(ctx context.Context, logger *slog.Logger, tokens idtoken.IDToken, userinfo *types.UserInfo) (types.UserInfo, error) {
	return p.Provider.GetUser(ctx, logger, tokens, userinfo)
}