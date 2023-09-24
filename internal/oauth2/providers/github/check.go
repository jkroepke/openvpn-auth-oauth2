package github

import (
	"context"
	"fmt"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/types"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

type orgType struct {
	Login string `json:"login"`
}

type teamType struct {
	Name string  `json:"name"`
	Org  orgType `json:"organization"`
	Slug string  `json:"slug"`
}

func (p *Provider) CheckUser(ctx context.Context, _ *state.State, _ *types.UserData, tokens *oidc.Tokens[*oidc.IDTokenClaims]) error {
	tokens.IDTokenClaims = &oidc.IDTokenClaims{
		Claims: make(map[string]any),
	}

	if len(p.Provider.Conf.Oauth2.Validate.Groups) != 0 {
		orgs, err := requestApi[[]orgType](ctx, tokens.AccessToken, "/user/orgs")
		if err != nil {
			return err
		}
		var groups []interface{}
		for _, org := range *orgs {
			groups = append(groups, org.Login)
		}

		tokens.IDTokenClaims.Claims["groups"] = groups

		err = p.CheckGroups(tokens)
		if err != nil {
			return err
		}
	}
	if len(p.Provider.Conf.Oauth2.Validate.Roles) != 0 {
		teams, err := requestApi[[]teamType](ctx, tokens.AccessToken, "/user/teams")
		if err != nil {
			return err
		}
		var roles []interface{}
		for _, team := range *teams {
			roles = append(roles, fmt.Sprintf("%s:%s", team.Org.Login, team.Slug))
		}

		tokens.IDTokenClaims.Claims["roles"] = roles

		err = p.CheckRoles(tokens)
		if err != nil {
			return err
		}
	}

	return nil
}
