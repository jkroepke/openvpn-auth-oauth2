package state

import (
	"testing"
	"time"

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

func TestStateInvalid_Future(t *testing.T) {
	encryptionKey := "0123456789101112"

	state := New(1, 2, "127.0.0.1", "test")
	state.Issued = time.Now().Add(time.Hour)

	assert.NoError(t, state.Encode(encryptionKey))
	assert.Contains(t, state.Decode(encryptionKey).Error(), "state issued in future, issued at:")
}

func TestStateInvalid_TooOld(t *testing.T) {
	encryptionKey := "0123456789101112"

	state := New(1, 2, "127.0.0.1", "test")
	state.Issued = time.Now().Add(-1 * time.Hour)

	assert.NoError(t, state.Encode(encryptionKey))
	assert.Contains(t, state.Decode(encryptionKey).Error(), "state expired after 2 minutes, issued at:")
}

func TestStateInvalid_Encoded(t *testing.T) {
	encryptionKey := "0123456789101112"

	state := NewEncoded("test")
	assert.Error(t, state.Decode(encryptionKey))
}
