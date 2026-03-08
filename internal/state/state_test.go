package state_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/state"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/test/testsuite"
	"github.com/stretchr/testify/require"
)

func TestState(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		commonName   string
		sessionState string
	}{
		{name: "empty session state", commonName: "foobar", sessionState: ""},
		{name: "non-empty session state", commonName: "", sessionState: "Authenticated"},
		{name: "with special characters", commonName: "foo bar/baz@qux", sessionState: "AuthenticatedEmptyUser"},
		{name: "with unicode characters", commonName: "foo bar/baz@qux 你好", sessionState: "ExpiredEmptyUser"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sessionState := state.State{
				Client: state.ClientIdentifier{
					CID:        9223372036854775807,
					KID:        2,
					CommonName: tc.commonName,
				},
				IPAddr:       "127.0.0.1",
				IPPort:       "12345",
				SessionState: tc.sessionState,
			}

			encryptedToken, err := state.Encrypt(testsuite.Cipher, sessionState)
			require.NoError(t, err)

			token, err := state.Decrypt(testsuite.Cipher, encryptedToken)
			require.NoError(t, err)

			require.Equal(t, token, sessionState)
		})
	}
}

func TestStateInvalid(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		encodedToken func() (state.EncryptedState, error)
		expectedErr  string
	}{
		{
			name: "invalid base64",
			encodedToken: func() (state.EncryptedState, error) {
				return "invalid", nil
			},
			expectedErr: "illegal base64 data at input",
		},
		{
			name: "invalid ciphertext",
			encodedToken: func() (state.EncryptedState, error) {
				return base64.URLEncoding.EncodeToString([]byte("a")), nil
			},
			expectedErr: "ciphertext block size is too short",
		},
		{
			name: "invalid state too long",
			encodedToken: func() (state.EncryptedState, error) {
				return strings.Repeat("a", 10000), nil
			},
			expectedErr: "invalid state: token too large",
		},
		{
			name: "invalid CID",
			encodedToken: func() (state.EncryptedState, error) {
				encrypted, err := testsuite.Cipher.EncryptBytesWithTime([]byte("A B C D E F G H"))
				if err != nil {
					return "", err
				}

				return base64.URLEncoding.EncodeToString(encrypted), nil
			},
			expectedErr: "parse CID: strconv.ParseUint",
		},
		{
			name: "invalid KID",
			encodedToken: func() (state.EncryptedState, error) {
				encrypted, err := testsuite.Cipher.EncryptBytesWithTime([]byte("1 B C D E F G H"))
				if err != nil {
					return "", err
				}

				return base64.URLEncoding.EncodeToString(encrypted), nil
			},
			expectedErr: "parse KID: strconv.ParseUint",
		},
		{
			name: "invalid UsernameIsDefined",
			encodedToken: func() (state.EncryptedState, error) {
				encrypted, err := testsuite.Cipher.EncryptBytesWithTime([]byte("1 1 C D E F G H"))
				if err != nil {
					return "", err
				}

				return base64.URLEncoding.EncodeToString(encrypted), nil
			},
			expectedErr: "parse UsernameIsDefined: strconv.Atoi",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			encodedTokenString, err := tc.encodedToken()
			require.NoError(t, err)

			_, err = state.Decrypt(testsuite.Cipher, encodedTokenString)

			require.ErrorContains(t, err, tc.expectedErr)
		})
	}
}
