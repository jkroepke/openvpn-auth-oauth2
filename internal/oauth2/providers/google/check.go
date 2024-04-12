package google

import (
	"context"
	"errors"

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
		tokens.IDTokenClaims.Groups = []string{}

		if tokens.AccessToken == "" {
			return errors.New("access token is empty")
		}

		for _, group := range p.Conf.OAuth2.Validate.Groups {
			isMember, err := p.checkGroupMembership(ctx, group, userData, tokens)
			if err != nil {
				return err
			}

			if isMember {
				tokens.IDTokenClaims.Groups = append(tokens.IDTokenClaims.Groups, group)
			}
		}
	}

	return p.Provider.CheckUser(ctx, session, userData, tokens) //nolint:wrapcheck
}
