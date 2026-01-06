package generic

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
)

func (p Provider) CheckUser(
	_ context.Context,
	session state.State,
	userInfo types.UserInfo,
	tokens idtoken.IDToken,
) error {
	if err := p.CheckGroups(userInfo); err != nil {
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

func (p Provider) CheckRoles(tokens idtoken.IDToken) error {
	if len(p.Conf.OAuth2.Validate.Roles) == 0 {
		return nil
	}

	if tokens.IDTokenClaims == nil {
		return fmt.Errorf("%w: id_token", oauth2.ErrMissingClaim)
	}

	if tokens.IDTokenClaims.Roles == nil {
		return fmt.Errorf("%w: roles", oauth2.ErrMissingClaim)
	}

	for _, role := range p.Conf.OAuth2.Validate.Roles {
		if slices.Contains(tokens.IDTokenClaims.Roles, role) {
			return nil
		}
	}

	return oauth2.ErrMissingRequiredRole
}

func (p Provider) CheckCommonName(session state.State, tokens idtoken.IDToken) error {
	if p.Conf.OAuth2.Validate.CommonName == "" {
		return nil
	}

	if session.Client.CommonName == "" || session.Client.CommonName == config.CommonNameModeOmitValue {
		return fmt.Errorf("common_name %w: openvpn client is empty", oauth2.ErrMismatch)
	}

	tokenCommonName, err := p.getTokenCommonName(tokens)
	if err != nil {
		return err
	}

	clientValue := p.getClientValue(session.Client.CommonName)

	// Apply case insensitivity
	if !p.Conf.OAuth2.Validate.CommonNameCaseSensitive {
		clientValue = strings.ToLower(clientValue)
		tokenCommonName = strings.ToLower(tokenCommonName)
	}

	if tokenCommonName != clientValue {
		return fmt.Errorf("common_name %w: openvpn client: %s - oidc token: %s",
			oauth2.ErrMismatch, clientValue, tokenCommonName)
	}

	return nil
}

// getTokenCommonName extracts and transforms the common name from the ID token claims.
func (p Provider) getTokenCommonName(tokens idtoken.IDToken) (string, error) {
	if tokens.IDTokenClaims == nil {
		return "", fmt.Errorf("%w: id_token", oauth2.ErrMissingClaim)
	}

	if tokens.IDTokenClaims.Claims == nil {
		return "", fmt.Errorf("%w: id_token.claims", oauth2.ErrMissingClaim)
	}

	tokenCommonName, ok := tokens.IDTokenClaims.Claims[p.Conf.OAuth2.Validate.CommonName].(string)
	if !ok {
		return "", fmt.Errorf("%w: %s", oauth2.ErrMissingClaim, p.Conf.OAuth2.Validate.CommonName)
	}

	return utils.TransformCommonName(p.Conf.OpenVPN.CommonName.Mode, tokenCommonName), nil
}

// getClientValue returns the client value to compare against the token.
// If email validation with regexp transformation is configured, it transforms the common name to email.
func (p Provider) getClientValue(commonName string) string {
	if p.Conf.OAuth2.Validate.CommonName == "email" && p.Conf.OAuth2.Validate.CommonNameEmailRegexp != nil {
		return transformCommonNameToEmail(commonName, p.Conf.OAuth2.Validate.CommonNameEmailRegexp)
	}

	return commonName
}

// transformCommonNameToEmail transforms a common name to an email address using regexp replacement.
func transformCommonNameToEmail(commonName string, regexpConf *config.CommonNameEmailRegexp) string {
	re := regexp.MustCompile(regexpConf.Pattern)

	return re.ReplaceAllString(commonName, regexpConf.Replacement)
}

func (p Provider) CheckIPAddress(session state.State, tokens idtoken.IDToken) error {
	if !p.Conf.OAuth2.Validate.IPAddr {
		return nil
	}

	if tokens.IDTokenClaims == nil {
		return fmt.Errorf("%w: id_token", oauth2.ErrMissingClaim)
	}

	if tokens.IDTokenClaims.IPAddr == "" {
		return fmt.Errorf("%w: ipaddr", oauth2.ErrMissingClaim)
	}

	if tokens.IDTokenClaims.IPAddr != session.IPAddr {
		return fmt.Errorf("ipaddr %w: openvpn client: %s - oidc token: %s",
			oauth2.ErrMismatch, tokens.IDTokenClaims.IPAddr, session.IPAddr)
	}

	return nil
}
