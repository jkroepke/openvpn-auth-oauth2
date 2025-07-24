package google

import (
	"context"
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
)

func (p Provider) GetUser(ctx context.Context, logger *slog.Logger, tokens idtoken.IDToken, userInfo *types.UserInfo) (types.UserInfo, error) {
	return p.Provider.GetUser(ctx, logger, tokens, userInfo) //nolint:wrapcheck
}
