package deny_test

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/deny"
	"github.com/stretchr/testify/require"
)

func TestReason(t *testing.T) {
	t.Parallel()

	tests := []struct {
		text     string
		reason   deny.Reason
		internal bool
	}{
		{"client rejected", deny.ClientRejected, false},
		{"OpenVPN Client does not support SSO authentication via webauth", deny.SSONotSupported, false},
		{"client re-authentication not enabled", deny.ReAuthenticationDisabled, false},
		{"client session state invalid or expired", deny.SessionStateInvalid, false},
		{"invalid client config", deny.InvalidClientConfig, false},
		{"invalid profile selection", deny.InvalidProfileSelection, false},
		{"internal error", deny.InternalError, true},
		{"unable to fetch user data", deny.UserDataUnavailable, true},
		{"unable to create profile selector", deny.ProfileSelectorUnavailable, true},
		{"client configuration not found", deny.ClientConfigUnavailable, true},
		{"authentication acceptance failed", deny.AcceptFailed, true},
		{"internal error", deny.Reason(0), true},
	}

	for _, tc := range tests {
		t.Run(tc.text, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tc.text, tc.reason.String())
			require.Equal(t, tc.internal, tc.reason.Internal())
			// The text is embedded in a quoted management command.
			require.NotContains(t, tc.reason.String(), `"`)
			require.False(t, strings.ContainsAny(tc.reason.String(), "\r\n"))

			if tc.internal {
				require.Equal(t, http.StatusInternalServerError, tc.reason.HTTPStatus())
				require.Equal(t, slog.LevelError, tc.reason.LogLevel())
			} else {
				require.Equal(t, http.StatusForbidden, tc.reason.HTTPStatus())
				require.Equal(t, slog.LevelWarn, tc.reason.LogLevel())
			}
		})
	}
}

func TestWrap(t *testing.T) {
	t.Parallel()

	require.NoError(t, deny.Wrap(deny.InternalError, nil))

	errBase := errors.New("base")
	err := fmt.Errorf("outer: %w", deny.Wrap(deny.ClientConfigUnavailable, errBase))

	require.ErrorIs(t, err, errBase)
	require.EqualError(t, err, "outer: base")
	require.Equal(t, deny.ClientConfigUnavailable, deny.ReasonOf(err, deny.AcceptFailed))
	require.Equal(t, deny.AcceptFailed, deny.ReasonOf(errBase, deny.AcceptFailed))
	require.Equal(t, deny.AcceptFailed, deny.ReasonOf(nil, deny.AcceptFailed))
}
