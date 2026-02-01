package oauth2

import (
	"fmt"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
)

type CELAuthMode string

const (
	CELAuthModeInteractive    CELAuthMode = "interactive"
	CELAuthModeNonInteractive CELAuthMode = "non-interactive"
)

// CheckTokenCEL checks the provided ID token claims against the configured CEL expression.
func (c *Client) CheckTokenCEL(authMode CELAuthMode, session state.State, tokens idtoken.IDToken) error {
	if c.celEvalPrg == nil {
		return nil
	}

	if tokens == nil || tokens.IDTokenClaims == nil {
		return ErrNoIDTokenAvailable
	}

	vars := map[string]any{
		"authMode":              string(authMode),
		"openVPNSessionState":   session.SessionState,
		"openVPNUserCommonName": session.Client.CommonName,
		"openVPNUserIPAddr":     session.IPAddr,
		"oauth2TokenClaims":     tokens.IDTokenClaims.Claims,
	}

	result, _, err := c.celEvalPrg.Eval(vars)
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
