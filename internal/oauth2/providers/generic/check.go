package generic

import (
	"context"
	"errors"
	"slices"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

func (p *Provider) CheckUser(_ context.Context, session *state.State, _ *types.UserData, tokens *oidc.Tokens[*oidc.IDTokenClaims]) error {
	if err := p.CheckGroups(tokens); err != nil {
		return err
	}
	if err := p.CheckRoles(tokens); err != nil {
		return err
	}
	if err := p.CheckCommonName(session, tokens); err != nil {
		return err
	}
	if err := p.CheckIpAddress(session, tokens); err != nil {
		return err
	}

	return nil
}

func (p *Provider) CheckGroups(tokens *oidc.Tokens[*oidc.IDTokenClaims]) error {
	if len(p.Conf.Oauth2.Validate.Groups) == 0 {
		return nil
	}

	tokenGroups, ok := tokens.IDTokenClaims.Claims["groups"]
	if !ok {
		return errors.New("missing groups claim")
	}

	tokenGroupsList := utils.CastToSlice[string](tokenGroups)

	for _, group := range p.Conf.Oauth2.Validate.Groups {
		if !slices.Contains(tokenGroupsList, group) {
			return errors.New(utils.StringConcat("missing required group ", group))
		}
	}

	return nil
}

func (p *Provider) CheckRoles(tokens *oidc.Tokens[*oidc.IDTokenClaims]) error {
	if len(p.Conf.Oauth2.Validate.Roles) == 0 {
		return nil
	}

	tokenRoles, ok := tokens.IDTokenClaims.Claims["roles"]
	if !ok {
		return errors.New("missing roles claim")
	}

	tokenRolesList := utils.CastToSlice[string](tokenRoles)

	for _, role := range p.Conf.Oauth2.Validate.Roles {
		if !slices.Contains(tokenRolesList, role) {
			return errors.New(utils.StringConcat("missing required role ", role))
		}
	}

	return nil
}
func (p *Provider) CheckCommonName(session *state.State, tokens *oidc.Tokens[*oidc.IDTokenClaims]) error {
	if p.Conf.Oauth2.Validate.CommonName == "" {
		return nil
	}

	tokenCommonName, ok := tokens.IDTokenClaims.Claims[p.Conf.Oauth2.Validate.CommonName].(string)
	if !ok {
		return errors.New(utils.StringConcat("missing ", p.Conf.Oauth2.Validate.CommonName, " claim"))
	}

	if tokenCommonName != session.CommonName {
		return errors.New(utils.StringConcat("common_name mismatch: openvpn client: ", tokenCommonName, " - oidc token: ", session.CommonName))
	}

	return nil
}
func (p *Provider) CheckIpAddress(session *state.State, tokens *oidc.Tokens[*oidc.IDTokenClaims]) error {
	if !p.Conf.Oauth2.Validate.IpAddr {
		return nil
	}

	tokenIpaddr, ok := tokens.IDTokenClaims.Claims["ipaddr"].(string)
	if !ok {
		return errors.New("missing ipaddr claim")
	}

	if tokenIpaddr != session.Ipaddr {
		return errors.New(utils.StringConcat("ipaddr mismatch: openvpn client: ", tokenIpaddr, " - oidc token: ", session.Ipaddr))
	}

	return nil
}
