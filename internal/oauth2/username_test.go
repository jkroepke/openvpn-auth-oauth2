//nolint:testpackage
package oauth2

import (
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/state"
	"github.com/stretchr/testify/require"
)

func TestResolveUsername(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		expression string
		authMode   CELAuthMode
		token      *idtoken.IDToken
		user       types.UserInfo
		expected   string
		err        string
	}{
		{
			name:       "normalized provider username",
			expression: "user.username",
			authMode:   CELAuthModeInteractive,
			user:       types.UserInfo{Username: "provider-user"},
			expected:   "provider-user",
		},
		{
			name:       "UserInfo email",
			expression: `user.email.split("@")[0]`,
			authMode:   CELAuthModeInteractive,
			user:       types.UserInfo{Email: "alice@example.com"},
			expected:   "alice",
		},
		{
			name:       "token claim",
			expression: "string(token.claims.sub)",
			authMode:   CELAuthModeInteractive,
			token: &idtoken.IDToken{
				IDTokenClaims: &idtoken.Claims{Claims: map[string]any{"sub": "token-user"}},
			},
			expected: "token-user",
		},
		{
			name:       "shared authentication and OpenVPN context",
			expression: `auth.mode + "-" + openvpn.commonName`,
			authMode:   CELAuthModeNonInteractive,
			expected:   "non-interactive-client-cn",
		},
		{
			name:       "normalized provider role",
			expression: "user.roles[0]",
			authMode:   CELAuthModeInteractive,
			user:       types.UserInfo{Roles: []string{"provider-role"}},
			expected:   "provider-role",
		},
		{
			name:       "empty result falls back to common name",
			expression: `""`,
			authMode:   CELAuthModeInteractive,
			expected:   "client-cn",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			conf := config.Defaults
			conf.OAuth2.OpenVPNUsername = tc.expression
			client := Client{conf: &conf}

			require.NoError(t, client.initializeUsernameResolver())

			username, err := client.resolveUsername(
				tc.authMode,
				state.State{Client: state.ClientIdentifier{CommonName: "client-cn"}},
				tc.token,
				tc.user,
			)
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.expected, username)
		})
	}
}

func TestResolveUsernameWithoutExpressionUsesCommonName(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	conf.OAuth2.OpenVPNUsername = ""
	client := Client{conf: &conf}

	require.NoError(t, client.initializeUsernameResolver())

	username, err := client.resolveUsername(
		CELAuthModeInteractive,
		state.State{Client: state.ClientIdentifier{CommonName: "client-cn"}},
		nil,
		types.UserInfo{Username: "provider-user"},
	)

	require.NoError(t, err)
	require.Equal(t, "client-cn", username)
}

func TestInitializeUsernameResolverRejectsInvalidExpressions(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		expression string
		err        string
	}{
		{
			name:       "invalid syntax",
			expression: "string(token.claims.sub",
			err:        "failed to compile CEL expression",
		},
		{
			name:       "boolean result",
			expression: "true",
			err:        "cel expression must evaluate to string, got bool",
		},
		{
			name:       "typed context result",
			expression: "user.groups",
			err:        "cel expression must evaluate to string, got list(string)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			conf := config.Defaults
			conf.OAuth2.OpenVPNUsername = tc.expression
			client := Client{conf: &conf}

			require.ErrorContains(t, client.initializeUsernameResolver(), tc.err)
		})
	}
}
