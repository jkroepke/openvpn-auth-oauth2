package google

import (
	"context"
	"errors"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
)

// CheckUser resolves Google group membership when configured and then runs generic user validation.
func (p Provider) CheckUser(
	ctx context.Context,
	session state.State,
	userData types.UserInfo,
	tokens *idtoken.IDToken,
) error {
	if len(p.Conf.OAuth2.Validate.Groups) > 0 {
		if err := p.resolveGroupMemberships(ctx, &userData, tokens); err != nil {
			return err
		}
	}

	return p.Provider.CheckUser(ctx, session, userData, tokens) //nolint:wrapcheck
}

// resolveGroupMemberships replaces userData.Groups with the subset of configured
// required groups that the user is a member of. Membership is resolved either
// directly (default) or transitively when GroupsTransitive is enabled.
func (p Provider) resolveGroupMemberships(ctx context.Context, userData *types.UserInfo, tokens *idtoken.IDToken) error {
	if tokens.AccessToken == "" {
		return errors.New("access token is empty")
	}

	userData.Groups = make([]string, 0)

	for _, group := range p.Conf.OAuth2.Validate.Groups {
		isMember, err := p.isGroupMember(ctx, group, *userData, tokens)
		if err != nil {
			return err
		}

		if isMember {
			userData.Groups = append(userData.Groups, group)
		}
	}

	return nil
}

// isGroupMember dispatches to the direct or transitive membership check based on configuration.
func (p Provider) isGroupMember(ctx context.Context, group string, userData types.UserInfo, tokens *idtoken.IDToken) (bool, error) {
	if p.Conf.Provider.Google.Validate.GroupsTransitive {
		return p.checkTransitiveGroupMembership(ctx, group, userData, tokens)
	}

	return p.checkGroupMembership(ctx, group, userData, tokens)
}
