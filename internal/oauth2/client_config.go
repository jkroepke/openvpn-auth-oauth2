package oauth2

import (
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"strings"
	"unicode"

	"cel.dev/cel-go/cel"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/state"
)

// initializeClientConfigResolver compiles the optional CEL expression used to resolve client configs.
func (c *Client) initializeClientConfigResolver() error {
	if c.conf.OpenVPN.ClientConfig.Expression == "" {
		return nil
	}

	program, err := compileCELProgram(c.conf.OpenVPN.ClientConfig.Expression, cel.ListType(cel.StringType))
	if err != nil {
		return fmt.Errorf("failed to initialize client config CEL expression: %w", err)
	}

	c.configsCELPrg = program

	return nil
}

// ResolveClientConfigNames returns the ordered client config names for an authenticated user.
func (c *Client) ResolveClientConfigNames(
	authMode CELAuthMode,
	session state.State,
	tokens *idtoken.IDToken,
	user types.UserInfo,
) ([]string, error) {
	if !c.conf.OpenVPN.ClientConfig.Enabled {
		return nil, nil
	}

	if c.conf.OpenVPN.ClientConfig.Expression == "" {
		return nil, errors.New("client config expression is not configured")
	}

	return c.resolveClientConfigNamesCEL(authMode, session, tokens, user)
}

func (c *Client) resolveClientConfigNamesCEL(
	authMode CELAuthMode,
	session state.State,
	tokens *idtoken.IDToken,
	user types.UserInfo,
) ([]string, error) {
	if c.configsCELPrg == nil {
		return nil, errors.New("client config CEL expression is not initialized")
	}

	out, _, err := c.configsCELPrg.Eval(newCELActivation(authMode, session, tokens, user))
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate CEL expression for client configs: %w", err)
	}

	nativeValue, err := out.ConvertToNative(reflect.TypeFor[[]string]())
	if err != nil {
		return nil, fmt.Errorf("%w: CEL expression for client configs did not evaluate to a string list", types.ErrInvalidClaimType)
	}

	names, ok := nativeValue.([]string)
	if !ok {
		return nil, fmt.Errorf("%w: CEL expression for client configs did not evaluate to a string list: %T", types.ErrInvalidClaimType, nativeValue)
	}

	return validateClientConfigNames(names)
}

func validateClientConfigNames(names []string) ([]string, error) {
	for _, name := range names {
		if name == "" {
			return nil, fmt.Errorf("%w: client config name is empty", types.ErrInvalidClaimType)
		}

		clientConfigPath := name + ".conf"
		if !fs.ValidPath(clientConfigPath) {
			return nil, fmt.Errorf("%w: invalid client config path %q", types.ErrInvalidClaimType, clientConfigPath)
		}

		if clientConfigNameUnsafe(name) {
			return nil, fmt.Errorf("%w: unsafe client config name %q", types.ErrInvalidClaimType, name)
		}
	}

	return names, nil
}

func clientConfigNameUnsafe(name string) bool {
	if strings.ContainsAny(name, `<>"'&`+"`") {
		return true
	}

	return strings.ContainsFunc(name, unicode.IsControl)
}
