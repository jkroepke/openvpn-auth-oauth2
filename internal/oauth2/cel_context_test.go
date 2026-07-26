package oauth2 //nolint:testpackage // The CEL environment and activation are internal implementation details.

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/idtoken"
	oauth2types "github.com/jkroepke/openvpn-auth-oauth2/v2/internal/oauth2/types"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCELContextSchema(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		expression   string
		expectedType *cel.Type
		err          string
	}{
		{
			name:         "authentication field",
			expression:   "auth.mode",
			expectedType: cel.StringType,
		},
		{
			name:         "OpenVPN field",
			expression:   "openvpn.commonName",
			expectedType: cel.StringType,
		},
		{
			name:         "OpenVPN IP field",
			expression:   "openvpn.ip",
			expectedType: cel.StringType,
		},
		{
			name:         "OpenVPN session state field",
			expression:   "openvpn.sessionState",
			expectedType: cel.StringType,
		},
		{
			name:         "token claims field",
			expression:   "token.claims",
			expectedType: cel.MapType(cel.StringType, cel.DynType),
		},
		{
			name:         "token field",
			expression:   "token.ip",
			expectedType: cel.StringType,
		},
		{
			name:         "dynamic token claim",
			expression:   "token.claims.department",
			expectedType: cel.DynType,
		},
		{
			name:         "normalized user email field",
			expression:   "user.email",
			expectedType: cel.StringType,
		},
		{
			name:         "normalized user groups field",
			expression:   "user.groups",
			expectedType: cel.ListType(cel.StringType),
		},
		{
			name:         "normalized user roles field",
			expression:   "user.roles",
			expectedType: cel.ListType(cel.StringType),
		},
		{
			name:         "normalized user subject field",
			expression:   "user.subject",
			expectedType: cel.StringType,
		},
		{
			name:         "normalized user username field",
			expression:   "user.username",
			expectedType: cel.StringType,
		},
		{
			name:       "unknown authentication field",
			expression: "auth.unknown",
			err:        "undefined field 'unknown'",
		},
		{
			name:       "unknown OpenVPN field",
			expression: "openvpn.unknown",
			err:        "undefined field 'unknown'",
		},
		{
			name:       "unknown token field",
			expression: "token.unknown",
			err:        "undefined field 'unknown'",
		},
		{
			name:       "unknown user field",
			expression: "user.unknown",
			err:        "undefined field 'unknown'",
		},
		{
			name:       "incompatible normalized user operation",
			expression: `user.groups == "vpn-users"`,
			err:        "found no matching overload for '_==_'",
		},
		{
			name:       "map-style user access",
			expression: `user["username"]`,
			err:        "found no matching overload for '_[_]'",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env, err := newCELEnvironment()
			require.NoError(t, err)

			ast, issues := env.Compile(tc.expression)
			if tc.err != "" {
				require.ErrorContains(t, issues.Err(), tc.err)

				return
			}

			require.NoError(t, issues.Err())
			assert.True(t, ast.OutputType().IsExactType(tc.expectedType), "expected %s, got %s", tc.expectedType, ast.OutputType())
		})
	}
}

func TestCELContextEvaluation(t *testing.T) {
	t.Parallel()

	program, err := compileCELProgram(`
		has(auth.mode) &&
		has(openvpn.commonName) &&
		has(openvpn.ip) &&
		has(openvpn.sessionState) &&
		has(token.claims) &&
		has(token.ip) &&
		has(user.email) &&
		has(user.groups) &&
		has(user.roles) &&
		has(user.subject) &&
		has(user.username) &&
		!has(token.claims.missing) &&
		auth == auth &&
		openvpn == openvpn &&
		token == token &&
		user == user &&
		auth.mode == "interactive" &&
		openvpn.commonName == user.username &&
		openvpn.ip == "192.0.2.10" &&
		openvpn.sessionState == "authenticated" &&
		token.claims.department == "engineering" &&
		token.ip == "192.0.2.20" &&
		user.email == "alice@example.com" &&
		user.groups == ["vpn-users"] &&
		user.roles == ["vpn-admin"] &&
		user.subject == "user-123"
	`, cel.BoolType)
	require.NoError(t, err)

	out, _, err := program.Eval(newCELActivation(
		CELAuthModeInteractive,
		state.State{
			Client:       state.ClientIdentifier{CommonName: "alice"},
			IPAddr:       "192.0.2.10",
			SessionState: "authenticated",
		},
		&idtoken.IDToken{IDTokenClaims: &idtoken.Claims{
			Claims: map[string]any{"department": "engineering"},
			IPAddr: "192.0.2.20",
		}},
		oauth2types.UserInfo{
			Email:    "alice@example.com",
			Groups:   []string{"vpn-users"},
			Roles:    []string{"vpn-admin"},
			Subject:  "user-123",
			Username: "alice",
		},
	))
	require.NoError(t, err)
	assert.Equal(t, true, out.Value())
}

func TestCELContextEmptyValues(t *testing.T) {
	t.Parallel()

	program, err := compileCELProgram(`
		has(token.claims) &&
		has(user.groups) &&
		has(user.roles) &&
		size(token.claims) == 0 &&
		token.ip == "" &&
		user.groups == [] &&
		user.roles == []
	`, cel.BoolType)
	require.NoError(t, err)

	out, _, err := program.Eval(newCELActivation(
		CELAuthModeInteractive,
		state.State{},
		nil,
		oauth2types.UserInfo{},
	))
	require.NoError(t, err)
	assert.Equal(t, true, out.Value())
}
