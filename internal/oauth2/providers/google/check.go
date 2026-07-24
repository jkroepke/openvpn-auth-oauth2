package google

import (
	"context"
	"errors"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/types"
)

// resolveGroupMemberships replaces userData.Groups with the configured required
// groups that the user is a member of. Do not stop after the first match:
// client-specific configuration can depend on the complete resolved group list.
func (p Provider) resolveGroupMemberships(ctx context.Context, userData *types.UserInfo, tokens *idtoken.IDToken) error {
	if tokens.AccessToken == "" {
		return errors.New("access token is empty")
	}

	userData.Groups = make([]string, 0, len(p.Conf.OAuth2.Validate.Groups))

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
