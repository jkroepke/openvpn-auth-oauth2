package oidc

import (
	"context"
	"errors"
	"fmt"
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
			return fmt.Errorf("missing required group %s", group)
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
			return fmt.Errorf("missing required role %s", role)
		}
	}

	return nil
}
func (p *Provider) CheckCommonName(session *state.State, tokens *oidc.Tokens[*oidc.IDTokenClaims]) error {
	if p.Conf.Oauth2.Validate.CommonName == "" {
		return nil
	}

	tokenCommonName, ok := tokens.IDTokenClaims.Claims[p.Conf.Oauth2.Validate.CommonName]
	if !ok {
		return fmt.Errorf("missing %s claim", p.Conf.Oauth2.Validate.CommonName)
	}

	if tokenCommonName != session.CommonName {
		return fmt.Errorf("common_name mismatch: openvpn client: %s - oidc token: %s", tokenCommonName, session.CommonName)
	}

	return nil
}
func (p *Provider) CheckIpAddress(session *state.State, tokens *oidc.Tokens[*oidc.IDTokenClaims]) error {
	if !p.Conf.Oauth2.Validate.IpAddr {
		return nil
	}

	tokenIpaddr, ok := tokens.IDTokenClaims.Claims["ipaddr"]
	if !ok {
		return errors.New("missing ipaddr claim")
	}

	if tokenIpaddr != session.Ipaddr {
		return fmt.Errorf("ipaddr mismatch: openvpn client: %s - oidc token: %s", tokenIpaddr, session.Ipaddr)
	}

	return nil
}
