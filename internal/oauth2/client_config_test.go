//nolint:testpackage
package oauth2

import (
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/stretchr/testify/require"
)

func TestResolveClientConfigNamesExpression(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	conf.OpenVPN.ClientConfig.Enabled = true
	conf.OpenVPN.ClientConfig.Expression = `oauth2TokenClaims.groups.filter(g, g in ["base", "admin"]) + [username]`

	client := Client{conf: &conf}
	require.NoError(t, client.initializeClientConfigResolver())

	names, err := client.ResolveClientConfigNames(&idtoken.IDToken{
		IDTokenClaims: &idtoken.Claims{
			Claims: map[string]any{
				"groups": []any{"base", "ignored", "admin"},
			},
		},
	}, "client-cn", "alice")

	require.NoError(t, err)
	require.Equal(t, []string{"base", "admin", "alice"}, names)
}

func TestResolveClientConfigNamesExpressionUsesCommonNameAndUsername(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	conf.OpenVPN.ClientConfig.Enabled = true
	conf.OpenVPN.ClientConfig.Expression = `[openVPNUserCommonName, username]`

	client := Client{conf: &conf}
	require.NoError(t, client.initializeClientConfigResolver())

	names, err := client.ResolveClientConfigNames(
		&idtoken.IDToken{IDTokenClaims: &idtoken.Claims{Claims: map[string]any{}}},
		"client-cn",
		"alice",
	)

	require.NoError(t, err)
	require.Equal(t, []string{"client-cn", "alice"}, names)
}

func TestResolveClientConfigNamesExpressionRejectsInvalidName(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	conf.OpenVPN.ClientConfig.Enabled = true
	conf.OpenVPN.ClientConfig.Expression = `["../admin"]`

	client := Client{conf: &conf}
	require.NoError(t, client.initializeClientConfigResolver())

	_, err := client.ResolveClientConfigNames(&idtoken.IDToken{IDTokenClaims: &idtoken.Claims{Claims: map[string]any{}}}, "client-cn", "alice")

	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid client config path")
}

func TestInitializeClientConfigResolverRejectsScalarExpression(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	conf.OpenVPN.ClientConfig.Enabled = true
	conf.OpenVPN.ClientConfig.Expression = `"base"`

	client := Client{conf: &conf}

	err := client.initializeClientConfigResolver()

	require.Error(t, err)
	require.Contains(t, err.Error(), "must evaluate to list(string), got string")
}

func TestInitializeClientConfigResolverRejectsNonStringListExpression(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	conf.OpenVPN.ClientConfig.Enabled = true
	conf.OpenVPN.ClientConfig.Expression = `[1]`

	client := Client{conf: &conf}

	err := client.initializeClientConfigResolver()

	require.Error(t, err)
	require.Contains(t, err.Error(), "must evaluate to list(string), got list(int)")
}

func TestResolveClientConfigNamesExpressionRejectsMissingClaim(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	conf.OpenVPN.ClientConfig.Enabled = true
	conf.OpenVPN.ClientConfig.Expression = `oauth2TokenClaims.groups`

	client := Client{conf: &conf}
	require.NoError(t, client.initializeClientConfigResolver())

	_, err := client.ResolveClientConfigNames(&idtoken.IDToken{IDTokenClaims: &idtoken.Claims{Claims: map[string]any{}}}, "client-cn", "alice")

	require.Error(t, err)
}

func TestResolveClientConfigNamesRequiresExpression(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	conf.OpenVPN.ClientConfig.Enabled = true

	client := Client{conf: &conf}

	_, err := client.ResolveClientConfigNames(&idtoken.IDToken{IDTokenClaims: &idtoken.Claims{Claims: map[string]any{}}}, "client-cn", "alice")

	require.Error(t, err)
	require.Contains(t, err.Error(), "client config expression is not configured")
}
