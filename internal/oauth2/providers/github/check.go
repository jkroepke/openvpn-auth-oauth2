package github

import (
	"context"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
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
		apiUrl := "https://api.github.com/user/orgs"

		var groups []interface{}

		for {
			var (
				orgs []orgType
				err  error
			)

			if apiUrl, err = get[[]orgType](ctx, tokens.AccessToken, apiUrl, &orgs); err != nil {
				return err
			}
			for _, org := range orgs {
				groups = append(groups, org.Login)
			}

			if apiUrl == "" {
				break
			}
		}

		tokens.IDTokenClaims.Claims["groups"] = groups

		if err := p.CheckGroups(tokens); err != nil {
			return err
		}
	}
	if len(p.Provider.Conf.Oauth2.Validate.Roles) != 0 {
		apiUrl := "https://api.github.com/user/teams"

		var roles []interface{}

		for {
			var (
				teams []teamType
				err   error
			)

			if apiUrl, err = get[[]teamType](ctx, tokens.AccessToken, apiUrl, &teams); err != nil {
				return err
			}
			for _, team := range teams {
				roles = append(roles, utils.StringConcat(team.Org.Login, ":", team.Slug))
			}

			if apiUrl == "" {
				break
			}
		}

		tokens.IDTokenClaims.Claims["roles"] = roles

		if err := p.CheckRoles(tokens); err != nil {
			return err
		}
	}

	return nil
}
