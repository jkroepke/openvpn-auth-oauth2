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
		4 << compactKindBits, 't', 'e', 's', 't', // compactKindText
		127, 0, 0, 1,
		2<<compactKindBits | compactKindDecimal, 0x30, 0x39,
		2<<compactKindBits | compactKindHex, 0xab, 0xcd,
	}, payload)
}

func TestCompactString(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		text       string
		kind       byte
		storedSize int
	}{
		{text: "", kind: compactKindText},
		{text: "0", kind: compactKindDecimal},
		{text: "12345", kind: compactKindDecimal, storedSize: 2},
		{text: "0123", kind: compactKindHex, storedSize: 2},
		{text: "007", kind: compactKindText, storedSize: 3},
		{text: "1234567890123456789012345678901234567890123456", kind: compactKindDecimal, storedSize: 19},
		{text: "0123456789abcdef0123456789abcdef", kind: compactKindHex, storedSize: 16},
		{text: "ABCD", kind: compactKindText, storedSize: 4},
		{text: "abc", kind: compactKindText, storedSize: 3},
		{text: "0a", kind: compactKindHex, storedSize: 1},
		{text: "0a:1b:ff", kind: compactKindColonHex, storedSize: 3},
		{text: "0a:1b:f", kind: compactKindText, storedSize: 7},
		{text: "0A:1B", kind: compactKindText, storedSize: 5},
		{text: "user@example.com", kind: compactKindText, storedSize: 16},
		{text: "foo bar/baz@qux 你好", kind: compactKindText, storedSize: len("foo bar/baz@qux 你好")},
	} {
		t.Run(tc.text, func(t *testing.T) {
			t.Parallel()

			encoded := appendCompactString(nil, tc.text)

			header, value, err := readUvarint(encoded)
			require.NoError(t, err)
			require.Equal(t, uint64(tc.kind), header&compactKindMask)
			require.Len(t, value, tc.storedSize)

			decoded, rest, err := readCompactString(encoded, nil)
			require.NoError(t, err)
			require.Empty(t, rest)
			require.Equal(t, tc.text, string(decoded))
		})
	}
}

func TestDecodeStateRejectsOlderVersion(t *testing.T) {
	t.Parallel()

	_, err := decodeState([]byte{2, 0, '3', 1, 2})
	require.EqualError(t, err, "unsupported state version: 2")
}

func TestDecodeStateRejectsTruncatedNonce(t *testing.T) {
	t.Parallel()

	_, err := decodeState([]byte{binaryStateVersion, flagNonce, '3', 1, 2, 16<<compactKindBits | compactKindHex, 0xab})
	require.ErrorContains(t, err, "read Nonce: string length 16 exceeds remaining data 1")

	_, err = decodeState([]byte{binaryStateVersion, flagNonce, '3', 1, 2})
	require.ErrorContains(t, err, "read Nonce: invalid uvarint")
}
