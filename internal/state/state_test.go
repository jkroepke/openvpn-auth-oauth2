package state_test

import (
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/stretchr/testify/assert"
)

func TestState(t *testing.T) {
	t.Parallel()

	encryptionKey := "0123456789101112"

	for i := 1; i < 50; i++ {
		token := state.New(1, 2, "127.0.0.1", "test")
		assert.NoError(t, token.Encode(encryptionKey))

		encodedToken := state.NewEncoded(token.Encoded())
		assert.NoError(t, encodedToken.Decode(encryptionKey))

		assert.Equal(t, token.Cid, encodedToken.Cid)
		assert.Equal(t, token.Kid, encodedToken.Kid)
		assert.Equal(t, token.Ipaddr, encodedToken.Ipaddr)
		assert.Equal(t, token.CommonName, encodedToken.CommonName)
	}
}

func TestStateInvalid_Key(t *testing.T) {
	t.Parallel()

	encryptionKey := "01234567891011"

	token := state.New(1, 2, "127.0.0.1", "test")
	assert.Error(t, token.Encode(encryptionKey), "crypto/aes: invalid key size 14")
}

func TestStateInvalid_Future(t *testing.T) {
	t.Parallel()

	encryptionKey := "0123456789101112"

	token := state.New(1, 2, "127.0.0.1", "test")
	token.Issued = time.Now().Add(time.Hour)

	assert.NoError(t, token.Encode(encryptionKey))
	assert.Contains(t, token.Decode(encryptionKey).Error(), "invalid state: issued in future, issued at:")
}

func TestStateInvalid_TooOld(t *testing.T) {
	t.Parallel()

	encryptionKey := "0123456789101112"

	token := state.New(1, 2, "127.0.0.1", "test")
	token.Issued = time.Now().Add(-1 * time.Hour)

	assert.NoError(t, token.Encode(encryptionKey))
	assert.Contains(t, token.Decode(encryptionKey).Error(), "invalid state: expired after 2 minutes, issued at:")
}

func TestStateInvalid_Encoded(t *testing.T) {
	t.Parallel()

	encryptionKey := "0123456789101112"

	token := state.NewEncoded("test")
	assert.Error(t, token.Decode(encryptionKey))
}
