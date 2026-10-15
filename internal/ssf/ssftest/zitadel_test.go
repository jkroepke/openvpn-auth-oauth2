package ssftest_test

import (
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/ssf/ssftest"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type setClaims struct {
	ssftest.SET

	algorithm jose.SignatureAlgorithm
}

func (c *setClaims) SetSignatureAlgorithm(algorithm jose.SignatureAlgorithm) {
	c.algorithm = algorithm
}

// TestZitadelKeySet checks that SETs from the transmitter verify with the
// zitadel/oidc key set the receiver uses, including key rotation.
func TestZitadelKeySet(t *testing.T) {
	t.Parallel()

	transmitter := ssftest.New(t)
	keySet := rp.NewRemoteKeySet(transmitter.Client(), transmitter.JWKSURI())

	check := func(token string) error {
		var claims setClaims

		payload, err := oidc.ParseToken(token, &claims)
		require.NoError(t, err)

		err = oidc.CheckSignature(t.Context(), token, payload, &claims, []string{string(jose.RS256)}, keySet)
		if err == nil {
			require.Equal(t, jose.RS256, claims.algorithm)
			require.Equal(t, transmitter.Issuer(), claims.Issuer)
		}

		return err
	}

	set := transmitter.NewSessionRevoked(ssftest.IssSub(transmitter.Issuer(), "user-1"))

	require.NoError(t, check(transmitter.Sign(t, set)))

	transmitter.RotateKey(t)
	require.NoError(t, check(transmitter.Sign(t, set)), "an unknown kid must trigger a JWK Set refresh")

	require.ErrorIs(t, check(transmitter.Sign(t, set, ssftest.WithUnpublishedKey(t))), oidc.ErrSignatureInvalid)
}
