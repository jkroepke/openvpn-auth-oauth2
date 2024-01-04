package github

import (
	"context"
	"fmt"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
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

// CheckUser implements the [github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2.Provider] interface.
// It checks if mets specific GitHub related conditions
func (p *Provider) CheckUser(
	ctx context.Context, _ state.State, _ types.UserData, tokens *oidc.Tokens[*idtoken.Claims],
) error {
	//nolint: exhaustruct
	tokens.IDTokenClaims = &idtoken.Claims{
		Claims: make(map[string]any),
	}

	if err := p.checkOrganizations(ctx, tokens); err != nil {
		return err
	}

	return p.checkTeams(ctx, tokens)
}

// checkTeams checks if the user is in a specific GitHub team by accessing the GitHub API.
func (p *Provider) checkTeams(ctx context.Context, tokens *oidc.Tokens[*idtoken.Claims]) error {
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

// checkOrganizations checks if the user is in a specific GitHub organization by accessing the GitHub API.
func (p *Provider) checkOrganizations(ctx context.Context, tokens *oidc.Tokens[*idtoken.Claims]) error {
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
