package google

import (
	"context"
	"fmt"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func (p *Provider) CheckUser(
	ctx context.Context,
	session state.State,
	userData types.UserData,
	tokens *oidc.Tokens[*idtoken.Claims],
) error {
	if len(p.Conf.OAuth2.Validate.Groups) > 0 {
		if tokens.AccessToken == "" {
			return fmt.Errorf("access token is empty")
		}

		groups, err := p.fetchGroupsFromIdentityAPI(ctx, userData, tokens)
		if err != nil {
			return err
		}

		tokens.IDTokenClaims.Groups = groups
	}

	return p.Provider.CheckUser(ctx, session, userData, tokens) //nolint:wrapcheck
}
