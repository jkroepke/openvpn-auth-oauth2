package oauth2

import (
	"fmt"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
)

// CheckTokenCEL checks the provided ID token claims against the configured CEL expression.
func (c *Client) CheckTokenCEL(session state.State, tokens idtoken.IDToken) error {
	if c.celEvalPrg == nil {
		return nil
	}

	if tokens == nil || tokens.IDTokenClaims == nil {
		return ErrNoIDTokenAvailable
	}

	vars := map[string]any{
		"openvpnUserCommonName": session.Client.CommonName,
		"openvpnUserIPAddr":     session.IPAddr,
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

	if resultValue != true {
		return ErrCELValidationFailed
	}

	return nil
}
