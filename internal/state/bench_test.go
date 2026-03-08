package state_test

import (
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/test/testsuite"
	"github.com/stretchr/testify/require"
)

func BenchmarkState(b *testing.B) {
	b.StopTimer()

	sessionState := state.State{
		Client: state.ClientIdentifier{
			CID:        9223372036854775807,
			KID:        2,
			CommonName: "test",
		},
		IPAddr:       "127.0.0.1",
		IPPort:       "12345",
		SessionState: "",
	}

	b.StartTimer()

	b.Run("encode", func(b *testing.B) {
		for b.Loop() {
			_, _ = state.Encrypt(testsuite.Cipher, sessionState)
		}

		b.ReportAllocs()
	})

	b.StopTimer()

	encodedTokenString, err := state.Encrypt(testsuite.Cipher, sessionState)
	require.NoError(b, err)

	b.StartTimer()

	b.Run("decode", func(b *testing.B) {
		for b.Loop() {
			_, _ = state.Decrypt(testsuite.Cipher, encodedTokenString)
		}

		b.ReportAllocs()
	})

	b.StopTimer()
}
