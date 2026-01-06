package state_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v3/pkg/crypto"
)

func TestState(t *testing.T) {
	t.Parallel()

	encryptionKey := testutils.Secret

	for i := 1; i < 50; i++ {
		token := state.New(state.ClientIdentifier{CID: 9223372036854775807, KID: 2, CommonName: "test"}, "127.0.0.1", "12345", "")
		encodedTokenString, err := token.Encode(encryptionKey)
		require.NoError(t, err)

		encodedToken, err := state.NewWithEncodedToken(encodedTokenString, encryptionKey)
		require.NoError(t, err)

		assert.Equal(t, token.Client.CID, encodedToken.Client.CID)
		assert.Equal(t, token.Client.KID, encodedToken.Client.KID)
		assert.Equal(t, token.Client.CommonName, encodedToken.Client.CommonName)
		assert.Equal(t, token.IPAddr, encodedToken.IPAddr)
	}
}

func TestStateWithEmptyValues(t *testing.T) {
	t.Parallel()

	encryptionKey := testutils.Secret

	token := state.New(state.ClientIdentifier{CID: 1, KID: 2, CommonName: ""}, "127.0.0.1", "12345", "")
	encodedTokenString, err := token.Encode(encryptionKey)
	require.NoError(t, err)

	encodedToken, err := state.NewWithEncodedToken(encodedTokenString, encryptionKey)
	require.NoError(t, err)

	assert.Equal(t, token.Client.CID, encodedToken.Client.CID)
	assert.Equal(t, token.Client.KID, encodedToken.Client.KID)
	assert.Equal(t, token.Client.CommonName, encodedToken.Client.CommonName)
}

func TestStateInvalid_Key(t *testing.T) {
	t.Parallel()

	encryptionKey := "01234567891011"

	token := state.New(state.ClientIdentifier{CID: 1, KID: 2, CommonName: "test"}, "127.0.0.1", "12345", "")
	_, err := token.Encode(encryptionKey)

	require.Error(t, err, "crypto/aes: invalid key size 14")
}

func TestState_WithSpace(t *testing.T) {
	t.Parallel()

	encryptionKey := testutils.Secret

	token := state.New(state.ClientIdentifier{CID: 1, KID: 2, CommonName: "t e s t"}, "127.0.0.1", "12345", "")

	encodedTokenString, err := token.Encode(encryptionKey)

	require.NoError(t, err)

	encodedToken, err := state.NewWithEncodedToken(encodedTokenString, encryptionKey)
	require.NoError(t, err)

	assert.Equal(t, token.Client.CID, encodedToken.Client.CID)
	assert.Equal(t, token.Client.KID, encodedToken.Client.KID)
	assert.Equal(t, token.Client.CommonName, encodedToken.Client.CommonName)
}

func TestState_WithState(t *testing.T) {
	t.Parallel()

	encryptionKey := testutils.Secret

	for _, sessionState := range []string{"", "Empty", "Initial", "Authenticated", "Expired", "Invalid", "AuthenticatedEmptyUser", "ExpiredEmptyUser"} {
		t.Run(sessionState, func(t *testing.T) {
			t.Parallel()

			token := state.New(state.ClientIdentifier{CID: 1, KID: 2, CommonName: "test"}, "127.0.0.1", "12345", sessionState)

			encodedTokenString, err := token.Encode(encryptionKey)

			require.NoError(t, err)

			encodedToken, err := state.NewWithEncodedToken(encodedTokenString, encryptionKey)
			require.NoError(t, err)

			assert.Equal(t, sessionState, encodedToken.SessionState)
		})
	}
}

func TestStateInvalid(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		encodedToken func() (string, error)
		expectedErr  string
	}{
		{
			name: "too old",
			encodedToken: func() (string, error) {
				token := state.New(state.ClientIdentifier{CID: 1, KID: 2, CommonName: "test"}, "127.0.0.1", "12345", "")
				// token.Issued = time.Now().Add(-1 * time.Hour).Unix()

				return token.Encode(testutils.Secret)
			},
			expectedErr: "invalid state: expired after 2 minutes, issued at:",
		},
		{
			name: "future",
			encodedToken: func() (string, error) {
				token := state.New(state.ClientIdentifier{CID: 1, KID: 2, CommonName: "test"}, "127.0.0.1", "12345", "")
				// token.Issued = time.Now().Add(time.Hour).Unix()

				return token.Encode(testutils.Secret)
			},
			expectedErr: "invalid state: issued in future, issued at:",
		},
		{
			name: "invalid base64",
			encodedToken: func() (string, error) {
				return "aaaaaa", nil
			},
			expectedErr: "illegal base64 data at input",
		},
		{
			name: "invalid ciphertext",
			encodedToken: func() (string, error) {
				return base64.URLEncoding.EncodeToString([]byte("a")), nil
			},
			expectedErr: "ciphertext block size is too short",
		},
		{
			name: "invalid state too long",
			encodedToken: func() (string, error) {
				return strings.Repeat("a", 10000), nil
			},
			expectedErr: "invalid state: token too large",
		},
		{
			name: "invalid AES key",
			encodedToken: func() (string, error) {
				encrypted, err := crypto.EncryptBytesAES([]byte("____"), testutils.Secret+testutils.Secret)
				if err != nil {
					return "", err
				}

				return base64.URLEncoding.EncodeToString(encrypted), nil
			},
			expectedErr: "invalid data format: no timestamp found",
		},
		{
			name: "invalid CID",
			encodedToken: func() (string, error) {
				token := fmt.Sprintf("%s A B C D E F G H I J %d", testutils.Secret[:2], time.Now().Unix())

				encrypted, err := crypto.EncryptBytesAES([]byte(token), testutils.Secret)
				if err != nil {
					return "", err
				}

				return base64.URLEncoding.EncodeToString(encrypted), nil
			},
			expectedErr: "parse CID: strconv.ParseUint",
		},
		{
			name: "invalid prefix",
			encodedToken: func() (string, error) {
				token := fmt.Sprintf("%s A B C D E F G H I J %d", "00", time.Now().Unix())

				encrypted, err := crypto.EncryptBytesAES([]byte(token), testutils.Secret)
				if err != nil {
					return "", err
				}

				return base64.URLEncoding.EncodeToString(encrypted), nil
			},
			expectedErr: "expected secret key prefix",
		},
		{
			name: "invalid KID",
			encodedToken: func() (string, error) {
				token := fmt.Sprintf("%s 1 B C D E F G H I J %d", testutils.Secret[:2], time.Now().Unix())

				encrypted, err := crypto.EncryptBytesAES([]byte(token), testutils.Secret)
				if err != nil {
					return "", err
				}

				return base64.URLEncoding.EncodeToString(encrypted), nil
			},
			expectedErr: "parse KID: strconv.ParseUint",
		},
		{
			name: "invalid UsernameIsDefined",
			encodedToken: func() (string, error) {
				token := fmt.Sprintf("%s 1 1 C D E F G H I J %d", testutils.Secret[:2], time.Now().Unix())

				encrypted, err := crypto.EncryptBytesAES([]byte(token), testutils.Secret)
				if err != nil {
					return "", err
				}

				return base64.URLEncoding.EncodeToString(encrypted), nil
			},
			expectedErr: "parse UsernameIsDefined: strconv.Atoi",
		},
		{
			name: "invalid issued",
			encodedToken: func() (string, error) {
				token := testutils.Secret[:2] + " 1 1 C D E 1 G H I J K"
				encrypted, err := crypto.EncryptBytesAES([]byte(token), testutils.Secret)
				if err != nil {
					return "", err
				}

				return base64.URLEncoding.EncodeToString(encrypted), nil
			},
			expectedErr: "parse Issued: strconv.ParseInt",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			encodedTokenString, err := tc.encodedToken()
			require.NoError(t, err)

			_, err = state.NewWithEncodedToken(encodedTokenString, testutils.Secret)

			require.ErrorContains(t, err, tc.expectedErr)
		})
	}
}

func TestStateInvalid_Encoded(t *testing.T) {
	t.Parallel()

	_, err := state.NewWithEncodedToken("test", testutils.Secret)
	require.Error(t, err)
}
