package authentik

import (
	"context"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
)

// CheckUser implements the [github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2.Provider] interface.
func (p Provider) CheckUser(ctx context.Context, session state.State, user types.UserInfo, tokens idtoken.IDToken) error {
	return p.Provider.CheckUser(ctx, session, user, tokens) //nolint:wrapcheck
}