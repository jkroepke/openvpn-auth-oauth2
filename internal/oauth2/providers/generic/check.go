package generic

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

func (p *Provider) CheckUser(
	_ context.Context,
	session state.State,
	_ types.UserData,
	tokens *oidc.Tokens[*idtoken.Claims],
) error {
	if err := p.CheckGroups(tokens); err != nil {
		return err
	}

	if err := p.CheckRoles(tokens); err != nil {
		return err
	}

	if err := p.CheckCommonName(session, tokens); err != nil {
		return err
	}

	return p.CheckIPAddress(session, tokens)
}

func (p *Provider) CheckGroups(tokens *oidc.Tokens[*idtoken.Claims]) error {
	if len(p.Conf.OAuth2.Validate.Groups) == 0 {
		return nil
	}

	if tokens.IDTokenClaims == nil {
		return fmt.Errorf("%w: id_token", ErrMissingClaim)
	}

	if tokens.IDTokenClaims.Groups == nil {
		return fmt.Errorf("%w: groups", ErrMissingClaim)
	}

	for _, group := range p.Conf.OAuth2.Validate.Groups {
		if slices.Contains(tokens.IDTokenClaims.Groups, group) {
			return nil
		}
	}

	return ErrMissingRequiredGroup
}

func (p *Provider) CheckRoles(tokens *oidc.Tokens[*idtoken.Claims]) error {
	if len(p.Conf.OAuth2.Validate.Roles) == 0 {
		return nil
	}

	if tokens.IDTokenClaims == nil {
		return fmt.Errorf("%w: id_token", ErrMissingClaim)
	}

	if tokens.IDTokenClaims.Roles == nil {
		return fmt.Errorf("%w: roles", ErrMissingClaim)
	}

	for _, role := range p.Conf.OAuth2.Validate.Roles {
		if slices.Contains(tokens.IDTokenClaims.Roles, role) {
			return nil
		}
	}

	return ErrMissingRequiredRole
}

func (p *Provider) CheckCommonName(session state.State, tokens *oidc.Tokens[*idtoken.Claims]) error {
	if p.Conf.OAuth2.Validate.CommonName == "" {
		return nil
	}

	if session.Client.CommonName == "" || session.Client.CommonName == config.CommonNameModeOmitValue {
		return fmt.Errorf("common_name %w: openvpn client is empty", ErrMismatch)
	}

	if tokens.IDTokenClaims == nil {
		return fmt.Errorf("%w: id_token", ErrMissingClaim)
	}

	if tokens.IDTokenClaims.Claims == nil {
		return fmt.Errorf("%w: id_token.claims", ErrMissingClaim)
	}

	tokenCommonName, ok := tokens.IDTokenClaims.Claims[p.Conf.OAuth2.Validate.CommonName].(string)
	if !ok {
		return fmt.Errorf("%w: %s", ErrMissingClaim, p.Conf.OAuth2.Validate.CommonName)
	}

	tokenCommonName = utils.TransformCommonName(p.Conf.OpenVpn.CommonName.Mode, tokenCommonName)

	if !p.Conf.OAuth2.Validate.CommonNameCaseSensitive {
		session.Client.CommonName = strings.ToLower(session.Client.CommonName)
		tokenCommonName = strings.ToLower(tokenCommonName)
	}

	if tokenCommonName != session.Client.CommonName {
		return fmt.Errorf("common_name %w: openvpn client: %s - oidc token: %s",
			ErrMismatch, session.Client.CommonName, tokenCommonName)
	}

	return nil
}

func (p *Provider) CheckIPAddress(session state.State, tokens *oidc.Tokens[*idtoken.Claims]) error {
	if !p.Conf.OAuth2.Validate.IPAddr {
		return nil
	}

	if tokens.IDTokenClaims == nil {
		return fmt.Errorf("%w: id_token", ErrMissingClaim)
	}

	if tokens.IDTokenClaims.IPAddr == "" {
		return fmt.Errorf("%w: ipaddr", ErrMissingClaim)
	}

	if tokens.IDTokenClaims.IPAddr != session.IPAddr {
		return fmt.Errorf("ipaddr %w: openvpn client: %s - oidc token: %s",
			ErrMismatch, tokens.IDTokenClaims.IPAddr, session.IPAddr)
	}

	return nil
}
