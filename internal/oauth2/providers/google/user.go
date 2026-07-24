package google

import (
	"context"
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/types"
)

// GetUser normalizes Google user data and resolves configured group memberships.
func (p Provider) GetUser(ctx context.Context, logger *slog.Logger, tokens *idtoken.IDToken, userInfo *types.UserInfo) (types.UserInfo, error) {
	user, err := p.Provider.GetUser(ctx, logger, tokens, userInfo)
	if err != nil {
		return types.UserInfo{}, err //nolint:wrapcheck
	}

	if len(p.Conf.OAuth2.Validate.Groups) > 0 {
		if err = p.resolveGroupMemberships(ctx, &user, tokens); err != nil {
			return types.UserInfo{}, err
		}
	}

	return user, nil
}
