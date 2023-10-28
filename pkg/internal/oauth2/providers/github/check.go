package github

import (
	"context"
	"fmt"

	"github.com/jkroepke/openvpn-auth-oauth2/pkg/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/pkg/internal/types"
	"github.com/jkroepke/openvpn-auth-oauth2/pkg/internal/utils"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type orgType struct {
	Login string `json:"login"`
}

type teamType struct {
	Name string  `json:"name"`
	Org  orgType `json:"organization"`
	Slug string  `json:"slug"`
}

func (p *Provider) CheckUser(
	ctx context.Context, _ state.State, _ types.UserData, tokens *oidc.Tokens[*oidc.IDTokenClaims],
) error {
	//nolint: exhaustruct
	tokens.IDTokenClaims = &oidc.IDTokenClaims{
		Claims: make(map[string]any),
	}

	if err := p.CheckOrgs(ctx, tokens); err != nil {
		return err
	}

	return p.CheckTeams(ctx, tokens)
}

func (p *Provider) CheckTeams(ctx context.Context, tokens *oidc.Tokens[*oidc.IDTokenClaims]) error {
	if len(p.Provider.Conf.OAuth2.Validate.Roles) != 0 {
		return nil
	}

	apiURL := "https://api.github.com/user/teams"

	var roles []interface{}

	for {
		var (
			teams []teamType
			err   error
		)

		if apiURL, err = get[[]teamType](ctx, tokens.AccessToken, apiURL, &teams); err != nil {
			return err
		}

		for _, team := range teams {
			roles = append(roles, utils.StringConcat(team.Org.Login, ":", team.Slug))
		}

		if apiURL == "" {
			break
		}
	}

	tokens.IDTokenClaims.Claims["roles"] = roles

	if err := p.CheckRoles(tokens); err != nil {
		return fmt.Errorf("CheckRoles: %w", err)
	}

	return nil
}

func (p *Provider) CheckOrgs(ctx context.Context, tokens *oidc.Tokens[*oidc.IDTokenClaims]) error {
	if len(p.Provider.Conf.OAuth2.Validate.Groups) != 0 {
		return nil
	}

	apiURL := "https://api.github.com/user/orgs"

	var groups []interface{}

	for {
		var (
			orgs []orgType
			err  error
		)

		if apiURL, err = get[[]orgType](ctx, tokens.AccessToken, apiURL, &orgs); err != nil {
			return err
		}

		for _, org := range orgs {
			groups = append(groups, org.Login)
		}

		if apiURL == "" {
			break
		}
	}

	tokens.IDTokenClaims.Claims["groups"] = groups

	if err := p.CheckGroups(tokens); err != nil {
		return fmt.Errorf("CheckGroups: %w", err)
	}

	return nil
}
