//nolint:testpackage
package oauth2

import (
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
	oauth2types "github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/state"
	"github.com/stretchr/testify/require"
)

func TestResolveClientConfigNamesExpression(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	conf.OpenVPN.ClientConfig.Enabled = true
	conf.OpenVPN.ClientConfig.Expression = `user.groups.filter(g, g in ["base", "admin"]) + [user.username]`

	client := Client{conf: &conf}
	require.NoError(t, client.initializeClientConfigResolver())

	names, err := client.ResolveClientConfigNames(
		CELAuthModeInteractive,
		state.State{Client: state.ClientIdentifier{CommonName: "client-cn"}},
		&idtoken.IDToken{IDTokenClaims: &idtoken.Claims{Claims: map[string]any{}}},
		oauth2types.UserInfo{
			Username: "alice",
			Groups:   []string{"base", "ignored", "admin"},
		},
	)

	require.NoError(t, err)
	require.Equal(t, []string{"base", "admin", "alice"}, names)
}

func TestResolveClientConfigNamesExpressionUsesCommonNameAndUsername(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	conf.OpenVPN.ClientConfig.Enabled = true
	conf.OpenVPN.ClientConfig.Expression = `[openvpn.commonName, user.username]`

	client := Client{conf: &conf}
	require.NoError(t, client.initializeClientConfigResolver())

	names, err := client.ResolveClientConfigNames(
		CELAuthModeInteractive,
		state.State{Client: state.ClientIdentifier{CommonName: "client-cn"}},
		&idtoken.IDToken{IDTokenClaims: &idtoken.Claims{Claims: map[string]any{}}},
		oauth2types.UserInfo{Username: "alice"},
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

	_, err := client.ResolveClientConfigNames(
		CELAuthModeInteractive,
		state.State{Client: state.ClientIdentifier{CommonName: "client-cn"}},
		&idtoken.IDToken{IDTokenClaims: &idtoken.Claims{Claims: map[string]any{}}},
		oauth2types.UserInfo{Username: "alice"},
	)

	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid client config path")
}

func TestResolveClientConfigNamesExpressionRejectsUnsafeName(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	conf.OpenVPN.ClientConfig.Enabled = true
	conf.OpenVPN.ClientConfig.Expression = `["profile\" autofocus onfocus=alert(1)"]`

	client := Client{conf: &conf}
	require.NoError(t, client.initializeClientConfigResolver())

	_, err := client.ResolveClientConfigNames(
		CELAuthModeInteractive,
		state.State{Client: state.ClientIdentifier{CommonName: "client-cn"}},
		&idtoken.IDToken{IDTokenClaims: &idtoken.Claims{Claims: map[string]any{}}},
		oauth2types.UserInfo{Username: "alice"},
	)

	require.Error(t, err)
	require.Contains(t, err.Error(), "unsafe client config name")
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
	conf.OpenVPN.ClientConfig.Expression = `token.claims.groups`

	client := Client{conf: &conf}
	require.NoError(t, client.initializeClientConfigResolver())

	_, err := client.ResolveClientConfigNames(
		CELAuthModeInteractive,
		state.State{Client: state.ClientIdentifier{CommonName: "client-cn"}},
		&idtoken.IDToken{IDTokenClaims: &idtoken.Claims{Claims: map[string]any{}}},
		oauth2types.UserInfo{Username: "alice"},
	)

	require.Error(t, err)
}

func TestResolveClientConfigNamesRequiresExpression(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	conf.OpenVPN.ClientConfig.Enabled = true

	client := Client{conf: &conf}

	_, err := client.ResolveClientConfigNames(
		CELAuthModeInteractive,
		state.State{Client: state.ClientIdentifier{CommonName: "client-cn"}},
		&idtoken.IDToken{IDTokenClaims: &idtoken.Claims{Claims: map[string]any{}}},
		oauth2types.UserInfo{Username: "alice"},
	)

	require.Error(t, err)
	require.Contains(t, err.Error(), "client config expression is not configured")
}
