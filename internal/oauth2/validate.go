package oauth2

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

func validateToken(conf *config.Config, session *state.State, tokens *oidc.Tokens[*oidc.IDTokenClaims]) error {
	if err := validateGroups(conf, tokens); err != nil {
		return err
	}
	if err := validateRoles(conf, tokens); err != nil {
		return err
	}
	if err := validateCommonName(conf, session, tokens); err != nil {
		return err
	}
	if err := validateIpAddr(conf, session, tokens); err != nil {
		return err
	}

	return nil
}

func validateGroups(conf *config.Config, tokens *oidc.Tokens[*oidc.IDTokenClaims]) error {
	if len(conf.Oauth2.Validate.Groups) == 0 {
		return nil
	}

	tokenGroups, ok := tokens.IDTokenClaims.Claims["groups"]
	if !ok {
		return errors.New("missing groups claim")
	}

	tokenGroupsList := strings.Split(fmt.Sprintf("%v", tokenGroups), ",")

	for _, group := range conf.Oauth2.Validate.Groups {
		if !slices.Contains(tokenGroupsList, group) {
			return fmt.Errorf("missing required group %s", group)
		}
	}

	return nil
}

func validateRoles(conf *config.Config, tokens *oidc.Tokens[*oidc.IDTokenClaims]) error {
	if len(conf.Oauth2.Validate.Roles) == 0 {
		return nil
	}

	tokenRoles, ok := tokens.IDTokenClaims.Claims["roles"]
	if !ok {
		return errors.New("missing roles claim")
	}

	tokenRolesList := strings.Split(fmt.Sprintf("%v", tokenRoles), ",")

	for _, role := range conf.Oauth2.Validate.Roles {
		if !slices.Contains(tokenRolesList, role) {
			return fmt.Errorf("missing required role %s", role)
		}
	}

	return nil
}
func validateCommonName(conf *config.Config, session *state.State, tokens *oidc.Tokens[*oidc.IDTokenClaims]) error {
	if conf.Oauth2.Validate.CommonName == "" {
		return nil
	}

	tokenCommonName, ok := tokens.IDTokenClaims.Claims[conf.Oauth2.Validate.CommonName]
	if !ok {
		return fmt.Errorf("missing %s claim", conf.Oauth2.Validate.CommonName)
	}

	if tokenCommonName != session.CommonName {
		return fmt.Errorf("common_name mismatch: openvpn client: %s - oidc token: %s", tokenCommonName, session.CommonName)
	}

	return nil
}
func validateIpAddr(conf *config.Config, session *state.State, tokens *oidc.Tokens[*oidc.IDTokenClaims]) error {
	if !conf.Oauth2.Validate.IpAddr {
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
