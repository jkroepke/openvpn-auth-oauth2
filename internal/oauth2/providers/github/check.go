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
// It checks if mets specific GitHub related conditions.
func (p *Provider) CheckUser(
	ctx context.Context, state state.State, userData types.UserData, tokens *oidc.Tokens[*idtoken.Claims],
) error {
	//nolint:exhaustruct
	tokens.IDTokenClaims = &idtoken.Claims{}

	orgs, err := p.getOrganizations(ctx, tokens)
	if err != nil {
		return fmt.Errorf("error getting GitHub organizations: %w", err)
	}

	tokens.IDTokenClaims.Groups = orgs

	teams, err := p.getTeams(ctx, tokens)
	if err != nil {
		return fmt.Errorf("error getting GitHub teams: %w", err)
	}

	tokens.IDTokenClaims.Roles = teams

	return p.Provider.CheckUser(ctx, state, userData, tokens) //nolint:wrapcheck
}

// getTeams fetch the users GitHub team by accessing the GitHub API.
func (p *Provider) getTeams(ctx context.Context, tokens *oidc.Tokens[*idtoken.Claims]) ([]string, error) {
	var roles []string

	if len(p.Provider.Conf.OAuth2.Validate.Roles) != 0 {
		return roles, nil
	}

	apiURL := "https://api.github.com/user/teams"

	for {
		var (
			teams []teamType
			err   error
		)

		if apiURL, err = get[[]teamType](ctx, p.httpClient, tokens.AccessToken, apiURL, &teams); err != nil {
			return nil, err
		}

		for _, team := range teams {
			roles = append(roles, utils.StringConcat(team.Org.Login, ":", team.Slug))
		}

		if apiURL == "" {
			break
		}
	}

	return roles, nil
}

// getOrganizations fetch the users GitHub organization by accessing the GitHub API.
func (p *Provider) getOrganizations(ctx context.Context, tokens *oidc.Tokens[*idtoken.Claims]) ([]string, error) {
	var groups []string

	if len(p.Provider.Conf.OAuth2.Validate.Groups) != 0 {
		return groups, nil
	}

	apiURL := "https://api.github.com/user/orgs"

	for {
		var (
			orgs []orgType
			err  error
		)

		if apiURL, err = get[[]orgType](ctx, p.httpClient, tokens.AccessToken, apiURL, &orgs); err != nil {
			return nil, err
		}

		for _, org := range orgs {
			groups = append(groups, org.Login)
		}

		if apiURL == "" {
			break
		}
	}

	return groups, nil
}
