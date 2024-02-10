package google

import (
	"context"
	"net/url"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func (p *Provider) CheckUser(
	ctx context.Context,
	session state.State,
	userData types.UserData,
	tokens *oidc.Tokens[*idtoken.Claims],
) error {
	if len(p.Conf.OAuth2.Validate.Groups) > 0 {
		groups, err := p.fetchGroupsFromAdminAPI(ctx, tokens)
		if err != nil {
			return err
		}

		tokens.IDTokenClaims.Groups = groups
	}

	return p.Provider.CheckUser(ctx, session, userData, tokens) //nolint:wrapcheck
}

// fetchGroupsFromAdminAPI fetches the groups of a user from the Google Admin API.
func (p *Provider) fetchGroupsFromAdminAPI(ctx context.Context, tokens *oidc.Tokens[*idtoken.Claims]) ([]string, error) {
	// https://developers.google.com/admin-sdk/directory/reference/rest/v1/groups/list
	apiURL := &url.URL{
		Scheme: "https",
		Host:   "admin.googleapis.com",
		Path:   "/admin/directory/v1/groups",
		RawQuery: utils.StringConcat(
			"domain=", tokens.IDTokenClaims.Hd,
			"&userKey=", tokens.IDTokenClaims.Subject,
			"&maxResults=200",
		),
	}

	var groups []string

	for {
		var (
			result groupPage
			err    error
		)

		if err = p.getAPI(ctx, apiURL, &result); err != nil {
			return nil, err
		}

		for _, group := range result.Groups {
			groups = append(groups, group.Email)
		}

		if apiURL.Query().Get("pageToken") == "" {
			break
		}
	}

	return groups, nil
}
