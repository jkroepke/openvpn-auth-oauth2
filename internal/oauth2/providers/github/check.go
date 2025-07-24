package github

import (
	"context"
	"errors"
	"fmt"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
)

type orgType struct {
	Login string `json:"login"`
}

type teamType struct {
	Org  orgType `json:"organization"`
	Slug string  `json:"slug"`
}

// CheckUser implements the [github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2.Provider] interface.
// It checks if it meets specific GitHub related conditions.
func (p Provider) CheckUser(
	ctx context.Context, sessionState state.State, userData types.UserInfo, tokens idtoken.IDToken,
) error {
	//nolint:exhaustruct
	tokens.IDTokenClaims = &idtoken.Claims{}

	if len(p.Conf.OAuth2.Validate.Groups) > 0 {
		organizations, err := p.getOrganizations(ctx, tokens)
		if err != nil {
			return fmt.Errorf("error getting GitHub organizations: %w", err)
		}

		userData.Groups = organizations
	}

	if len(p.Conf.OAuth2.Validate.Roles) > 0 {
		teams, err := p.getTeams(ctx, tokens)
		if err != nil {
			return fmt.Errorf("error getting GitHub teams: %w", err)
		}

		tokens.IDTokenClaims.Roles = teams
	}

	return p.Provider.CheckUser(ctx, sessionState, userData, tokens) //nolint:wrapcheck
}

// getTeams fetch the users GitHub team by accessing the GitHub API.
func (p Provider) getTeams(ctx context.Context, tokens idtoken.IDToken) ([]string, error) {
	if tokens.AccessToken == "" {
		return nil, errors.New("access token is empty")
	}

	var roles []string

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
func (p Provider) getOrganizations(ctx context.Context, tokens idtoken.IDToken) ([]string, error) {
	if tokens.AccessToken == "" {
		return nil, errors.New("access token is empty")
	}

	var groups []string

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
