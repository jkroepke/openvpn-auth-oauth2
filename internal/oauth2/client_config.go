package oauth2

import (
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"strings"
	"unicode"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/types"
)

// initializeClientConfigResolver compiles the optional CEL expression used to resolve client configs.
func (c *Client) initializeClientConfigResolver() error {
	if c.conf.OpenVPN.ClientConfig.Expression == "" {
		return nil
	}

	env, err := cel.NewEnv(
		cel.VariableWithDoc("openVPNUserCommonName", cel.StringType, "The common name of the OpenVPN user"),
		cel.VariableWithDoc("oauth2TokenClaims", cel.MapType(cel.StringType, cel.DynType), "The claims of the OAuth2 ID token"),
		cel.VariableWithDoc("username", cel.StringType, "The resolved OpenVPN username"),
		ext.Strings(ext.StringsVersion(5)),
		ext.Lists(ext.ListsVersion(3)),
	)
	if err != nil {
		return fmt.Errorf("failed to create client config CEL environment: %w", err)
	}

	prg, issues := env.Compile(c.conf.OpenVPN.ClientConfig.Expression)
	if issues.Err() != nil {
		return fmt.Errorf("failed to compile client config CEL expression: %w", issues.Err())
	}

	expectedType := cel.ListType(cel.StringType)
	if !prg.OutputType().IsAssignableType(expectedType) {
		return fmt.Errorf(
			"client config CEL expression must evaluate to %s, got %s",
			expectedType,
			prg.OutputType(),
		)
	}

	c.configsCELPrg, err = env.Program(prg)
	if err != nil {
		return fmt.Errorf("failed to create client config CEL program: %w", err)
	}

	return nil
}

// ResolveClientConfigNames returns the ordered client config names for an authenticated user.
func (c *Client) ResolveClientConfigNames(tokens *idtoken.IDToken, openVPNUserCommonName, username string) ([]string, error) {
	if !c.conf.OpenVPN.ClientConfig.Enabled {
		return nil, nil
	}

	if c.conf.OpenVPN.ClientConfig.Expression == "" {
		return nil, errors.New("client config expression is not configured")
	}

	return c.resolveClientConfigNamesCEL(tokens, openVPNUserCommonName, username)
}

func (c *Client) resolveClientConfigNamesCEL(tokens *idtoken.IDToken, openVPNUserCommonName, username string) ([]string, error) {
	if c.configsCELPrg == nil {
		return nil, errors.New("client config CEL expression is not initialized")
	}

	claims := make(map[string]any)
	if tokens != nil && tokens.IDTokenClaims != nil {
		claims = tokens.IDTokenClaims.Claims
	}

	out, _, err := c.configsCELPrg.Eval(map[string]any{
		"openVPNUserCommonName": openVPNUserCommonName,
		"oauth2TokenClaims":     claims,
		"username":              username,
	})
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
