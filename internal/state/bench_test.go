package state_test

import (
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/pkg/testutils"
)

func BenchmarkState(b *testing.B) {
	b.StopTimer()

	encryptionKey := testutils.Secret
	token := state.New(state.ClientIdentifier{CID: 9223372036854775807, KID: 2}, "127.0.0.1", "12345", "test")

	b.StartTimer()

	b.Run("encode", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = token.Encode(encryptionKey)
		}

		b.ReportAllocs()
	})

	b.StopTimer()

	encodedToken := state.NewEncoded(token.Encoded())

	b.StartTimer()

	b.Run("decode", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = encodedToken.Decode(encryptionKey)
		}

		b.ReportAllocs()
	})

	b.StopTimer()
}
