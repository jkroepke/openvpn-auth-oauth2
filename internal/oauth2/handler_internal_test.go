package oauth2

import (
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/test/testlogger"
	"github.com/stretchr/testify/require"
)

func TestWithIDTokenClaimsLoggerOmitsUnrestrictedClaims(t *testing.T) {
	t.Parallel()

	logger := testlogger.New()
	tokens := &idtoken.IDToken{
		IDTokenClaims: &idtoken.Claims{
			Claims: map[string]any{"custom_sensitive_claim": "secret-custom-claim"},
		},
	}
	tokens.IDTokenClaims.Subject = "subject"

	withIDTokenClaimsLogger(logger.Logger(), tokens).Info("test message")

	require.Contains(t, logger.String(), "idtoken_subject=subject")
	require.NotContains(t, logger.String(), "custom_sensitive_claim")
	require.NotContains(t, logger.String(), "secret-custom-claim")
}
