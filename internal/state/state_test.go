package state_test

import (
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestState(t *testing.T) {
	t.Parallel()

	encryptionKey := testutils.Secret

	for i := 1; i < 50; i++ {
		token := state.New(state.ClientIdentifier{CID: 9223372036854775807, KID: 2, CommonName: "test"}, "127.0.0.1", "12345")
		encodedTokenString, err := token.Encode(encryptionKey)
		require.NoError(t, err)

		encodedToken, err := state.NewWithEncodedToken(encodedTokenString, encryptionKey)
		require.NoError(t, err)

		assert.Equal(t, token.Client.CID, encodedToken.Client.CID)
		assert.Equal(t, token.Client.KID, encodedToken.Client.KID)
		assert.Equal(t, token.IPAddr, encodedToken.IPAddr)
		assert.Equal(t, token.Client.CommonName, encodedToken.Client.CommonName)
	}
}

func TestStateWithEmptyValues(t *testing.T) {
	t.Parallel()

	encryptionKey := testutils.Secret

	token := state.New(state.ClientIdentifier{CID: 1, KID: 2, CommonName: "test"}, "127.0.0.1", "12345")
	encodedTokenString, err := token.Encode(encryptionKey)
	require.NoError(t, err)

	encodedToken, err := state.NewWithEncodedToken(encodedTokenString, encryptionKey)
	require.NoError(t, err)

	assert.Equal(t, token.Client.CID, encodedToken.Client.CID)
	assert.Equal(t, token.Client.KID, encodedToken.Client.KID)
	assert.Equal(t, token.IPAddr, encodedToken.IPAddr)
	assert.Equal(t, token.Client.CommonName, encodedToken.Client.CommonName)
}

func TestStateInvalid_Key(t *testing.T) {
	t.Parallel()

	encryptionKey := "01234567891011"

	token := state.New(state.ClientIdentifier{CID: 1, KID: 2, CommonName: "test"}, "127.0.0.1", "12345")
	_, err := token.Encode(encryptionKey)

	require.Error(t, err, "crypto/aes: invalid key size 14")
}

func TestState_WithSpace(t *testing.T) {
	t.Parallel()

	encryptionKey := testutils.Secret

	token := state.New(state.ClientIdentifier{CID: 1, KID: 2, CommonName: "test"}, "127.0.0.1", "12345")

	encodedTokenString, err := token.Encode(encryptionKey)

	require.NoError(t, err)

	encodedToken, err := state.NewWithEncodedToken(encodedTokenString, encryptionKey)
	require.NoError(t, err)

	assert.Equal(t, token.Client.CID, encodedToken.Client.CID)
	assert.Equal(t, token.Client.KID, encodedToken.Client.KID)
	assert.Equal(t, token.IPAddr, encodedToken.IPAddr)
	assert.Equal(t, token.Client.CommonName, encodedToken.Client.CommonName)
}

func TestStateInvalid_Future(t *testing.T) {
	t.Parallel()

	encryptionKey := testutils.Secret

	token := state.New(state.ClientIdentifier{CID: 1, KID: 2, CommonName: "test"}, "127.0.0.1", "12345")
	token.Issued = time.Now().Add(time.Hour).Unix()
	encodedTokenString, err := token.Encode(encryptionKey)

	require.NoError(t, err)

	_, err = state.NewWithEncodedToken(encodedTokenString, encryptionKey)

	assert.ErrorContains(t, err, "invalid state: issued in future, issued at:")
}

func TestStateInvalid_TooOld(t *testing.T) {
	t.Parallel()

	encryptionKey := testutils.Secret

	token := state.New(state.ClientIdentifier{CID: 1, KID: 2, CommonName: "test"}, "127.0.0.1", "12345")
	token.Issued = time.Now().Add(-1 * time.Hour).Unix()
	encodedTokenString, err := token.Encode(encryptionKey)

	require.NoError(t, err)

	_, err = state.NewWithEncodedToken(encodedTokenString, encryptionKey)

	assert.ErrorContains(t, err, "invalid state: expired after 2 minutes, issued at:")
}

func TestStateInvalid_Encoded(t *testing.T) {
	t.Parallel()

	_, err := state.NewWithEncodedToken("test", testutils.Secret)
	require.Error(t, err)
}
