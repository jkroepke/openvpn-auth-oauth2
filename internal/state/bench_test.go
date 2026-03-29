package state_test

import (
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/test/testsuite"
	"github.com/stretchr/testify/require"
)

func benchmarkSessionState() state.State {
	return state.State{
		Client: state.ClientIdentifier{
			CID:        9223372036854775807,
			KID:        2,
			CommonName: "test",
		},
		IPAddr:       "127.0.0.1",
		IPPort:       "12345",
		SessionState: "",
	}
}

func BenchmarkStateEncrypt(b *testing.B) {
	sessionState := benchmarkSessionState()

	var encryptedState state.EncryptedState

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		var err error

		encryptedState, err = state.Encrypt(testsuite.Cipher, sessionState)
		if err != nil {
			b.Fatal(err)
		}
	}

	_ = encryptedState
}

func BenchmarkStateDecrypt(b *testing.B) {
	encodedTokenString, err := state.Encrypt(testsuite.Cipher, benchmarkSessionState())
	require.NoError(b, err)

	var decryptedState state.State

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		var decryptErr error

		decryptedState, decryptErr = state.Decrypt(testsuite.Cipher, encodedTokenString)
		if decryptErr != nil {
			b.Fatal(decryptErr)
		}
	}

	_ = decryptedState
}
