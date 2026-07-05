package generic

import (
	"context"
	"fmt"
	"slices"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/state"
)

// CheckUser validates the resolved user and ID token against the configured generic provider rules.
func (p Provider) CheckUser(
	_ context.Context,
	_ state.State,
	userInfo types.UserInfo,
	_ *idtoken.IDToken,
) error {
	return p.CheckGroups(userInfo)
}

// CheckGroups verifies that the user belongs to at least one required group.
func (p Provider) CheckGroups(userInfo types.UserInfo) error {
	if len(p.Conf.OAuth2.Validate.Groups) == 0 {
		return nil
	}

	if userInfo.Groups == nil {
		return fmt.Errorf("%w: groups", oauth2.ErrMissingClaim)
	}

	for _, group := range p.Conf.OAuth2.Validate.Groups {
		if slices.Contains(userInfo.Groups, group) {
			return nil
		}
	}

	return oauth2.ErrMissingRequiredGroup
}
