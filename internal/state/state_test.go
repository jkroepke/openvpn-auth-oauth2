package state_test

import (
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/pkg/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestState(t *testing.T) {
	t.Parallel()

	encryptionKey := testutils.Secret

	for i := 1; i < 50; i++ {
		token := state.New(state.ClientIdentifier{CID: 9223372036854775807, KID: 2}, "127.0.0.1", "test")
		require.NoError(t, token.Encode(encryptionKey))

		encodedToken := state.NewEncoded(token.Encoded())
		require.NoError(t, encodedToken.Decode(encryptionKey))

		assert.Equal(t, token.Client.CID, encodedToken.Client.CID)
		assert.Equal(t, token.Client.KID, encodedToken.Client.KID)
		assert.Equal(t, token.Ipaddr, encodedToken.Ipaddr)
		assert.Equal(t, token.CommonName, encodedToken.CommonName)
	}
}

func TestStateWithEmptyValues(t *testing.T) {
	t.Parallel()

	encryptionKey := testutils.Secret

	token := state.New(state.ClientIdentifier{CID: 1, KID: 2}, "127.0.0.1", "")
	require.NoError(t, token.Encode(encryptionKey))

	encodedToken := state.NewEncoded(token.Encoded())
	require.NoError(t, encodedToken.Decode(encryptionKey))

	assert.Equal(t, token.Client.CID, encodedToken.Client.CID)
	assert.Equal(t, token.Client.KID, encodedToken.Client.KID)
	assert.Equal(t, token.Ipaddr, encodedToken.Ipaddr)
	assert.Equal(t, token.CommonName, encodedToken.CommonName)
}

func TestStateInvalid_Key(t *testing.T) {
	t.Parallel()

	encryptionKey := "01234567891011"

	token := state.New(state.ClientIdentifier{CID: 1, KID: 2}, "127.0.0.1", "test")
	require.Error(t, token.Encode(encryptionKey), "crypto/aes: invalid key size 14")
}

func TestStateInvalid_Future(t *testing.T) {
	t.Parallel()

	encryptionKey := testutils.Secret

	token := state.New(state.ClientIdentifier{CID: 1, KID: 2}, "127.0.0.1", "test")
	token.Issued = time.Now().Add(time.Hour).Unix()

	require.NoError(t, token.Encode(encryptionKey))
	assert.Contains(t, token.Decode(encryptionKey).Error(), "invalid state: issued in future, issued at:")
}

func TestState_WithSpace(t *testing.T) {
	t.Parallel()

	encryptionKey := testutils.Secret

	token := state.New(state.ClientIdentifier{CID: 1, KID: 2}, "127.0.0.1", "te st")

	require.NoError(t, token.Encode(encryptionKey))

	encodedToken := state.NewEncoded(token.Encoded())
	require.NoError(t, encodedToken.Decode(encryptionKey))

	assert.Equal(t, token.Client.CID, encodedToken.Client.CID)
	assert.Equal(t, token.Client.KID, encodedToken.Client.KID)
	assert.Equal(t, token.Ipaddr, encodedToken.Ipaddr)
	assert.Equal(t, token.CommonName, encodedToken.CommonName)
}

func TestStateInvalid_TooOld(t *testing.T) {
	t.Parallel()

	encryptionKey := testutils.Secret

	token := state.New(state.ClientIdentifier{CID: 1, KID: 2}, "127.0.0.1", "test")
	token.Issued = time.Now().Add(-1 * time.Hour).Unix()

	require.NoError(t, token.Encode(encryptionKey))
	assert.Contains(t, token.Decode(encryptionKey).Error(), "invalid state: expired after 2 minutes, issued at:")
}

func TestStateInvalid_Encoded(t *testing.T) {
	t.Parallel()

	encryptionKey := testutils.Secret

	token := state.NewEncoded("test")
	require.Error(t, token.Decode(encryptionKey))
}
