package state

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestState(t *testing.T) {
	encryptionKey := "0123456789101112"

	for i := 1; i < 50; i++ {
		state := New(1, 2, "127.0.0.1", "test")
		assert.NoError(t, state.Encode(encryptionKey))

		encryptedState := NewEncoded(state.Encoded)
		assert.NoError(t, encryptedState.Decode(encryptionKey))

		assert.Equal(t, state.Cid, encryptedState.Cid)
		assert.Equal(t, state.Kid, encryptedState.Kid)
		assert.Equal(t, state.Ipaddr, encryptedState.Ipaddr)
		assert.Equal(t, state.CommonName, encryptedState.CommonName)
	}
}
func TestStateInvalid_Key(t *testing.T) {
	encryptionKey := "01234567891011"

	state := New(1, 2, "127.0.0.1", "test")
	assert.Error(t, state.Encode(encryptionKey), "crypto/aes: invalid key size 14")
}

func TestStateInvalid_Encoded(t *testing.T) {
	encryptionKey := "0123456789101112"

	state := NewEncoded("test")
	assert.Error(t, state.Decode(encryptionKey))
}
