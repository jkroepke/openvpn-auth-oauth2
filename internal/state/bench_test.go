package state_test

import (
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/stretchr/testify/require"
)

func BenchmarkState(b *testing.B) {
	b.StopTimer()

	encryptionKey := testutils.Secret
	token := state.New(state.ClientIdentifier{CID: 9223372036854775807, KID: 2}, "127.0.0.1", "12345", "test", "")

	b.StartTimer()

	b.Run("encode", func(b *testing.B) {
		for b.Loop() {
			_, _ = token.Encode(encryptionKey)
		}

		b.ReportAllocs()
	})

	b.StopTimer()

	encodedTokenString, err := token.Encode(encryptionKey)
	require.NoError(b, err)

	b.StartTimer()

	b.Run("decode", func(b *testing.B) {
		for b.Loop() {
			_, _ = state.NewWithEncodedToken(encodedTokenString, encryptionKey)
		}

		b.ReportAllocs()
	})

	b.StopTimer()
}
