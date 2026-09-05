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

func TestBuildClientPendingAuthCommand(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		client  connection.Client
		timeout time.Duration
		want    string
	}{
		{
			name:    "whole-second timeout",
			client:  connection.Client{CID: 12345, KID: 67890},
			timeout: 300 * time.Second,
			want:    `client-pending-auth 12345 67890 "WEB_AUTH::https://vpn.example.com/oauth2/start?state=encrypted-state" 300`,
		},
		{
			name:    "fractional timeout",
			client:  connection.Client{CID: 1, KID: 0},
			timeout: 1500 * time.Millisecond,
			want:    `client-pending-auth 1 0 "WEB_AUTH::https://vpn.example.com/oauth2/start?state=encrypted-state" 2`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			command, err := buildClientPendingAuthCommand(
				tc.client,
				"https://vpn.example.com/oauth2/start?state=encrypted-state",
				tc.timeout,
			)
			require.NoError(t, err)
			require.Equal(t, tc.want, command)
		})
	}
}

func TestBuildClientPendingAuthCommandLimit(t *testing.T) {
	t.Parallel()

	client := connection.Client{CID: 12345, KID: 0}

	command, err := buildClientPendingAuthCommand(client, strings.Repeat("a", 979), 300*time.Second)
	require.NoError(t, err)
	require.Len(t, command, openVPNManagementCommandBodyLimit)

	_, err = buildClientPendingAuthCommand(client, strings.Repeat("a", 980), 300*time.Second)
	require.EqualError(t, err, "client-pending-auth command is 1024 bytes; OpenVPN accepts at most 1023 bytes")
}
