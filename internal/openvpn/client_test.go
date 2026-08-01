package openvpn //nolint:testpackage // Verify the private command formatter's exact OpenVPN byte boundary.

import (
	"strings"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/openvpn/connection"
	"github.com/stretchr/testify/require"
)

func TestBuildOAuth2StartURL(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		baseURL string
		want    string
	}{
		{
			name:    "without trailing slash",
			baseURL: "https://vpn.example.com",
			want:    "https://vpn.example.com/oauth2/start?state=encrypted-state",
		},
		{
			name:    "with trailing slash",
			baseURL: "https://vpn.example.com/",
			want:    "https://vpn.example.com/oauth2/start?state=encrypted-state",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := buildOAuth2StartURL(tc.baseURL, "encrypted-state")
			require.Equal(t, tc.want, got)
		})
	}
}

func TestBuildClientPendingAuthCommandLimit(t *testing.T) {
	t.Parallel()

	client := connection.Client{CID: 1, KID: 0}

	command, err := buildClientPendingAuthCommand(client, strings.Repeat("a", 983), 300*time.Second)
	require.NoError(t, err)
	require.Len(t, command, openVPNManagementCommandBodyLimit)

	_, err = buildClientPendingAuthCommand(client, strings.Repeat("a", 984), 300*time.Second)
	require.EqualError(t, err, "client-pending-auth command is 1024 bytes; OpenVPN accepts at most 1023 bytes")
}
