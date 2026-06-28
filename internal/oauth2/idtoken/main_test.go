package idtoken_test

import (
	"encoding/json"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/oauth2/idtoken"
	"github.com/stretchr/testify/require"
)

func TestClaims_GetAccessTokenHash(t *testing.T) {
	t.Parallel()

	claims := idtoken.Claims{AccessTokenHash: "access-token-hash"}

	require.Equal(t, "access-token-hash", claims.GetAccessTokenHash())
}

func TestClaims_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	var claims idtoken.Claims

	err := json.Unmarshal([]byte(`{
		"iss": "https://issuer.example.com",
		"sub": "user-123",
		"preferred_username": "alice",
		"at_hash": "access-token-hash",
		"ipaddr": "192.0.2.10",
		"email": "alice@example.com",
		"groups": ["admin", "vpn"],
		"custom": {"enabled": true}
	}`), &claims)

	require.NoError(t, err)
	require.Equal(t, "https://issuer.example.com", claims.Issuer)
	require.Equal(t, "user-123", claims.Subject)
	require.Equal(t, "alice", claims.PreferredUsername)
	require.Equal(t, "access-token-hash", claims.AccessTokenHash)
	require.Equal(t, "192.0.2.10", claims.IPAddr)
	require.Equal(t, "alice@example.com", claims.EMail)
	require.Equal(t, "user-123", claims.Claims["sub"])
	require.Equal(t, []any{"admin", "vpn"}, claims.Claims["groups"])
	require.Equal(t, map[string]any{"enabled": true}, claims.Claims["custom"])
}

func TestClaims_UnmarshalJSONReturnsWrappedError(t *testing.T) {
	t.Parallel()

	var claims idtoken.Claims

	err := json.Unmarshal([]byte(`[]`), &claims)

	require.Error(t, err)
	require.Contains(t, err.Error(), "claims:")
	require.Contains(t, err.Error(), "*idtoken.Claims")
}
