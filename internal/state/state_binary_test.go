//nolint:testpackage
package state

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncodeStateUsesCompactBinaryPayload(t *testing.T) {
	t.Parallel()

	payload := encodeState(nil, State{
		Client: ClientIdentifier{
			CID:        1,
			KID:        2,
			CommonName: "test",
		},
		IPAddr:       "127.0.0.1",
		IPPort:       "12345",
		SessionState: sessionStateReverseMap[SessionStateAuthenticated],
		Nonce:        "abcd",
	})

	require.Equal(t, []byte{
		binaryStateVersion,
		flagCommonName | flagIPAddrV4 | flagIPPort | flagNonce,
		'3',
		1,
		2,
		4, 't', 'e', 's', 't',
		127, 0, 0, 1,
		5, '1', '2', '3', '4', '5',
		2<<1 | 1, 0xab, 0xcd,
	}, payload)
}

func TestEncodeStateStoresNonHexNonceAsText(t *testing.T) {
	t.Parallel()

	for _, nonce := range []string{"abc", "ABCD", "zz", "0123456789abcdeg", "nonce with spaces"} {
		payload := encodeState(nil, State{Nonce: nonce})

		state, err := decodeState(payload)
		require.NoError(t, err, nonce)
		require.Equal(t, nonce, state.Nonce)
	}
}

func TestEncodeStateStoresHexNonceRaw(t *testing.T) {
	t.Parallel()

	nonce := "0123456789abcdef0123456789abcdef"

	withNonce := encodeState(nil, State{Nonce: nonce})
	withoutNonce := encodeState(nil, State{})

	// One header byte plus the 16 raw bytes, instead of 1 + 32 as text.
	require.Len(t, withNonce, len(withoutNonce)+17)

	state, err := decodeState(withNonce)
	require.NoError(t, err)
	require.Equal(t, nonce, state.Nonce)
}

func TestDecodeStateRejectsOlderVersion(t *testing.T) {
	t.Parallel()

	_, err := decodeState([]byte{2, 0, '3', 1, 2})
	require.EqualError(t, err, "unsupported state version: 2")
}

func TestDecodeStateRejectsTruncatedNonce(t *testing.T) {
	t.Parallel()

	_, err := decodeState([]byte{binaryStateVersion, flagNonce, '3', 1, 2, 16<<1 | 1, 0xab})
	require.ErrorContains(t, err, "nonce length 16 exceeds remaining data 1")

	_, err = decodeState([]byte{binaryStateVersion, flagNonce, '3', 1, 2})
	require.ErrorContains(t, err, "read Nonce: invalid uvarint")
}
