//nolint:testpackage
package state

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncodeStateUsesCompactBinaryPayload(t *testing.T) {
	t.Parallel()

	payload := encodeState(State{
		Client: ClientIdentifier{
			CID:        1,
			KID:        2,
			CommonName: "test",
		},
		IPAddr:       "127.0.0.1",
		IPPort:       "12345",
		SessionState: sessionStateReverseMap[SessionStateAuthenticated],
	})

	require.Equal(t, []byte{
		binaryStateVersion,
		flagCommonName | flagIPAddrV4 | flagIPPort,
		'3',
		1,
		2,
		4, 't', 'e', 's', 't',
		127, 0, 0, 1,
		5, '1', '2', '3', '4', '5',
	}, payload.Bytes())
}
