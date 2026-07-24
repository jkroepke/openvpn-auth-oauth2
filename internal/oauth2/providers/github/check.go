package github

import (
	"context"
	"errors"
	"fmt"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
)

type orgType struct {
	Login string `json:"login"`
}

type teamType struct {
	Org  orgType `json:"organization"`
	Slug string  `json:"slug"`
}

// getTeams fetch the users GitHub teams by accessing the GitHub API.
func (p Provider) getTeams(ctx context.Context, tokens *idtoken.IDToken) ([]string, error) {
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
			roles = append(roles, fmt.Sprintf("%s:%s", team.Org.Login, team.Slug))
		}

		if apiURL == "" {
			break
		}
	}

	return roles, nil
}

// getOrganizations fetch the users GitHub organization by accessing the GitHub API.
func (p Provider) getOrganizations(ctx context.Context, tokens *idtoken.IDToken) ([]string, error) {
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
