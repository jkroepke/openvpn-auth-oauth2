package oauth2

import (
	"fmt"

	"github.com/google/cel-go/common/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
)

func (c Client) checkTokenCEL(session state.State, tokens idtoken.IDToken) error {
	if c.celEvalPrg == nil {
		return nil
	}

	vars := map[string]any{
		"openvpnCommonName": session.Client.CommonName,
		"openvpnIPAddr":     session.IPAddr,
		"tokenClaims":       tokens.IDTokenClaims.Claims,
	}

	result, _, err := c.celEvalPrg.Eval(vars)
	if err != nil {
		return fmt.Errorf("failed to evaluate CEL expression: %w", err)
	}

	if result.Equal(types.True) == types.True {
		return ErrCELValidationFailed
	}

	return nil
}
