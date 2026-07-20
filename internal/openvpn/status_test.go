package openvpn //nolint:testpackage // Exercise the status parser directly with malformed management output.

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

const status3ClientHeader = "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\t" +
	"Bytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher"

func TestStatusClientIDsByUsername(t *testing.T) {
	t.Parallel()

	status := status3ClientHeader + "\r\n" +
		status3ClientLine("alice", 7) + "\r\n" +
		status3ClientLine("Alice", 8) + "\r\n" +
		status3ClientLine("alice", 10) + "\r\n" +
		status3ClientLine("alice", 12) + "\r\n" +
		status3ClientLine("alice", 12) + "\r\nEND\r\n"

	clientIDs, err := statusClientIDsByUsername(status, "alice", 10)

	require.NoError(t, err)
	require.Equal(t, []uint64{7, 12}, clientIDs)
}

func TestStatusClientIDsByUsernameRejectsInvalidStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status string
		err    string
	}{
		{
			name:   "missing header",
			status: status3ClientLine("alice", 7) + "\nEND\n",
			err:    "client list header is missing Username or Client ID",
		},
		{
			name:   "missing client ID column",
			status: "HEADER\tCLIENT_LIST\tUsername\nEND\n",
			err:    "client list header is missing Username or Client ID",
		},
		{
			name:   "short client record",
			status: status3ClientHeader + "\nCLIENT_LIST\talice\nEND\n",
			err:    "client list record has 2 fields",
		},
		{
			name:   "invalid client ID",
			status: status3ClientHeader + "\n" + status3ClientLineWithID("alice", "invalid") + "\nEND\n",
			err:    `parse client list client ID "invalid"`,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			clientIDs, err := statusClientIDsByUsername(testCase.status, "alice", 10)

			require.ErrorContains(t, err, testCase.err)
			require.Nil(t, clientIDs)
		})
	}
}

func status3ClientLine(username string, clientID uint64) string {
	return status3ClientLineWithID(username, strconv.FormatUint(clientID, 10))
}

func status3ClientLineWithID(username, clientID string) string {
	return "CLIENT_LIST\tclient\t127.0.0.1:1194\t10.8.0.2\t\t1\t2\t2026-07-19 12:00:00\t1784455200\t" +
		username + "\t" + clientID + "\t0\tAES-256-GCM"
}
