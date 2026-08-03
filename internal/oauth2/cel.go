package oauth2

import (
	"errors"
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/state"
)

type CELAuthMode = types.AuthMode

const (
	CELAuthModeInteractive    = types.AuthModeInteractive
	CELAuthModeNonInteractive = types.AuthModeNonInteractive
)

// celActivation keeps the fixed CEL variables inline and resolves pointers to them,
// avoiding the map allocation and interface boxing required by map-based activations.
type celActivation struct {
	auth    celAuthContext
	openvpn celOpenVPNContext
	token   celTokenContext
	user    celUserContext
}

var _ cel.Activation = (*celActivation)(nil)

func (a *celActivation) ResolveName(name string) (any, bool) {
	switch name {
	case "auth":
		return &a.auth, true
	case "openvpn":
		return &a.openvpn, true
	case "token":
		return &a.token, true
	case "user":
		return &a.user, true
	default:
		return nil, false
	}
}

func (a *celActivation) Parent() cel.Activation {
	return nil
}

// newCELEnvironment returns the common CEL environment used by all configurable expressions.
func newCELEnvironment() (*cel.Env, error) {
	env, err := cel.NewEnv(
		celContextTypes(),
		cel.VariableWithDoc("auth", cel.ObjectType(celAuthContextTypeName), "Authentication context"),
		cel.VariableWithDoc("openvpn", cel.ObjectType(celOpenVPNContextTypeName), "OpenVPN session context"),
		cel.VariableWithDoc("token", cel.ObjectType(celTokenContextTypeName), "OAuth2 token context"),
		cel.VariableWithDoc("user", cel.ObjectType(celUserContextTypeName), "Normalized user context"),
		ext.Strings(ext.StringsVersion(5)),
		ext.Lists(ext.ListsVersion(4)),
	)
	if err != nil {
		return nil, fmt.Errorf("create CEL environment: %w", err)
	}

	return env, nil
}

func (c *Client) initializeCELPrograms() error {
	if err := c.initializeUsernameResolver(); err != nil {
		return err
	}

	if err := c.initializeCELValidation(); err != nil {
		return err
	}

	return c.initializeClientConfigResolver()
}

// initializeUsernameResolver compiles the optional CEL expression used to derive the OpenVPN username.
func (c *Client) initializeUsernameResolver() error {
	if c.conf.OAuth2.OpenVPNUsername == "" {
		return nil
	}

	program, err := compileCELProgram(c.conf.OAuth2.OpenVPNUsername, cel.StringType)
	if err != nil {
		return fmt.Errorf("failed to initialize username CEL expression: %w", err)
	}

	c.usernameCELPrg = program

	return nil
}

// initializeCELValidation compiles the configured CEL expression used for user validation.
func (c *Client) initializeCELValidation() error {
	if c.conf.OAuth2.Validate.Expression == "" {
		return nil
	}

	program, err := compileCELProgram(c.conf.OAuth2.Validate.Expression, cel.BoolType)
	if err != nil {
		return fmt.Errorf("failed to initialize validation CEL expression: %w", err)
	}

	c.validationCELPrg = program

	return nil
}

func compileCELProgram(expression string, expectedType *cel.Type) (cel.Program, error) {
	env, err := newCELEnvironment()
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	ast, issues := env.Compile(expression)
	if issues.Err() != nil {
		return nil, fmt.Errorf("failed to compile CEL expression: %w", issues.Err())
	}

	if expectedType != nil && !ast.OutputType().IsAssignableType(expectedType) {
		return nil, fmt.Errorf("cel expression must evaluate to %s, got %s", expectedType, ast.OutputType())
	}

	program, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL program: %w", err)
	}

	return program, nil
}

// resolveUsername evaluates the configured username expression against the normalized identity.
func (c *Client) resolveUsername(
	authMode CELAuthMode,
	session state.State,
	tokens *idtoken.IDToken,
	user types.UserInfo,
) (string, error) {
	if c.conf.OAuth2.OpenVPNUsername == "" {
		return session.Client.CommonName, nil
	}

	if c.usernameCELPrg == nil {
		return "", errors.New("username CEL expression is not initialized")
	}

	out, _, err := c.usernameCELPrg.Eval(newCELActivation(authMode, session, tokens, user))
	if err != nil {
		return "", fmt.Errorf("failed to evaluate CEL expression for username: %w", err)
	}

	username, ok := out.Value().(string)
	if !ok {
		return "", fmt.Errorf(
			"%w: CEL expression for username did not evaluate to a string: %T",
			types.ErrInvalidClaimType,
			out.Value(),
		)
	}

	if username == "" {
		return session.Client.CommonName, nil
	}

	return username, nil
}

// CheckIdentityCEL checks the normalized identity against the configured CEL expression.
func (c *Client) CheckIdentityCEL(
	authMode CELAuthMode,
	session state.State,
	tokens *idtoken.IDToken,
	user types.UserInfo,
) error {
	if c.validationCELPrg == nil {
		return nil
	}

	result, _, err := c.validationCELPrg.Eval(newCELActivation(authMode, session, tokens, user))
	if err != nil {
		return fmt.Errorf("failed to evaluate CEL expression: %w", err)
	}

	resultValue, ok := result.Value().(bool)
	if !ok {
		return ErrCELNoBooleanResult
	}

	if !resultValue {
		return ErrCELValidationFailed
	}

	return nil
}

func newCELActivation(
	authMode CELAuthMode,
	session state.State,
	tokens *idtoken.IDToken,
	userInfo types.UserInfo,
) *celActivation {
	var claims map[string]any

	tokenIP := ""

	if tokens != nil && tokens.IDTokenClaims != nil {
		tokenIP = tokens.IDTokenClaims.IPAddr

		if tokens.IDTokenClaims.Claims != nil {
			claims = tokens.IDTokenClaims.Claims
		}
	}

	groups := userInfo.Groups
	if groups == nil {
		groups = make([]string, 0)
	}

	roles := userInfo.Roles
	if roles == nil {
		roles = make([]string, 0)
	}

	return &celActivation{
		auth: celAuthContext{
			mode: string(authMode),
		},
		openvpn: celOpenVPNContext{
			commonName:   session.Client.CommonName,
			ip:           session.IPAddr,
			sessionState: session.SessionState,
		},
		token: celTokenContext{
			claims: claims,
			ip:     tokenIP,
		},
		user: celUserContext{
			email:    userInfo.Email,
			groups:   groups,
			roles:    roles,
			subject:  userInfo.Subject,
			username: userInfo.Username,
		},
	}
}
