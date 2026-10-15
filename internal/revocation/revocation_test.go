package revocation_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/metrics"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/revocation"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/sessionregistry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const issuer = "https://idp.example.com"

// recorder records the enforcement steps in order.
type recorder struct {
	refreshErr error
	killErr    error
	steps      []string
	mu         sync.Mutex
}

func (r *recorder) RevokeRefreshState(_ context.Context, _ *slog.Logger, entry sessionregistry.Entry) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := strconv.FormatUint(entry.CID, 10)
	if !entry.Connected {
		key = entry.OpenVPNSessionID
	}

	r.steps = append(r.steps, "refresh "+key)

	return r.refreshErr
}

func (r *recorder) KillClient(_ context.Context, _ *slog.Logger, clientID uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.steps = append(r.steps, "kill "+strconv.FormatUint(clientID, 10))

	return r.killErr
}

func (r *recorder) recorded() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]string(nil), r.steps...)
}

func identity(subject, sid string) sessionregistry.Identity {
	return sessionregistry.Identity{Issuer: issuer, Subject: subject, SessionID: sid}
}

func newEnforcer(t *testing.T, userLevel bool) (*revocation.Enforcer, *sessionregistry.Registry, *recorder, *metrics.Metrics) {
	t.Helper()

	conf := config.Defaults
	conf.SSF.UserLevelRevocation = userLevel

	sessions := sessionregistry.New()
	rec := &recorder{}
	appMetrics := metrics.New("test", "test")

	sessions.Add(sessionregistry.Entry{CID: 1, Username: "alice", Identity: identity("alice-sub", "sid-1")})
	sessions.Add(sessionregistry.Entry{CID: 2, Username: "alice", Identity: identity("alice-sub", "sid-2")})
	sessions.Add(sessionregistry.Entry{CID: 3, OpenVPNSessionID: "ovpn-3", Username: "alice", Identity: identity("alice-sub", "sid-3")})
	sessions.Add(sessionregistry.Entry{CID: 4, Username: "bob", Identity: identity("bob-sub", "sid-4")})
	_, ok := sessions.Disconnect(3, time.Hour)
	require.True(t, ok)

	return revocation.New(slog.New(slog.DiscardHandler), &conf, sessions, rec, rec, appMetrics), sessions, rec, appMetrics
}

func TestRevoke(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		subject   sessionregistry.Identity
		metric    string
		steps     []string
		remaining int
		userLevel bool
	}{
		{
			name:      "session level",
			subject:   sessionregistry.Identity{Issuer: issuer, SessionID: "sid-1"},
			userLevel: true,
			steps:     []string{"refresh 1", "kill 1"},
			metric:    `openvpn_auth_oauth2_ssf_sessions_revoked_total{scope="session"} 1`,
			remaining: 3,
		},
		{
			name:      "dormant session",
			subject:   sessionregistry.Identity{Issuer: issuer, SessionID: "sid-3"},
			userLevel: true,
			steps:     []string{"refresh ovpn-3"},
			metric:    `openvpn_auth_oauth2_ssf_sessions_revoked_total{scope="session"} 1`,
			remaining: 3,
		},
		{
			name:      "user level",
			subject:   sessionregistry.Identity{Issuer: issuer, Subject: "alice-sub"},
			userLevel: true,
			steps:     []string{"refresh 1", "kill 1", "refresh 2", "kill 2", "refresh ovpn-3"},
			metric:    `openvpn_auth_oauth2_ssf_sessions_revoked_total{scope="user"} 3`,
			remaining: 1,
		},
		{
			name:      "user level disabled",
			subject:   sessionregistry.Identity{Issuer: issuer, Subject: "alice-sub"},
			remaining: 4,
		},
		{
			name:      "session level with user level disabled",
			subject:   sessionregistry.Identity{Issuer: issuer, SessionID: "sid-2"},
			steps:     []string{"refresh 2", "kill 2"},
			metric:    `openvpn_auth_oauth2_ssf_sessions_revoked_total{scope="session"} 1`,
			remaining: 3,
		},
		{
			name:      "no match",
			subject:   sessionregistry.Identity{Issuer: issuer, SessionID: "sid-9"},
			userLevel: true,
			remaining: 4,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			enforcer, sessions, rec, appMetrics := newEnforcer(t, tc.userLevel)

			count, err := enforcer.Revoke(t.Context(), tc.subject)
			require.NoError(t, err)
			assert.Equal(t, tc.steps, rec.recorded())
			assert.Equal(t, 4-tc.remaining, count)
			assert.Equal(t, tc.remaining, sessions.Len())

			var output bytes.Buffer

			require.NoError(t, appMetrics.Write(&output))

			if tc.metric != "" {
				assert.Contains(t, output.String(), tc.metric)
			} else {
				assert.NotContains(t, output.String(), "ssf_sessions_revoked_total{")
			}

			// Applying the revocation again finds nothing left to do.
			count, err = enforcer.Revoke(t.Context(), tc.subject)
			require.NoError(t, err)
			assert.Zero(t, count)
		})
	}
}

func TestRevokedClientKeepsNoDormantEntry(t *testing.T) {
	t.Parallel()

	conf := config.Defaults
	sessions := sessionregistry.New()
	rec := &recorder{}
	enforcer := revocation.New(slog.New(slog.DiscardHandler), &conf, sessions, rec, rec, nil)

	sessions.Add(sessionregistry.Entry{CID: 1, OpenVPNSessionID: "ovpn-1", Identity: identity("alice-sub", "sid-1")})

	count, err := enforcer.Revoke(t.Context(), sessionregistry.Identity{Issuer: issuer, SessionID: "sid-1"})
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// The disconnect that follows the kill finds nothing to keep.
	_, ok := sessions.Disconnect(1, time.Hour)
	assert.False(t, ok)
	assert.Equal(t, 0, sessions.Len())
}

func TestRevokeIsRetriedAfterKillFailure(t *testing.T) {
	t.Parallel()

	enforcer, sessions, rec, _ := newEnforcer(t, true)
	rec.killErr = errors.New("management interface gone")

	subject := sessionregistry.Identity{Issuer: issuer, SessionID: "sid-1"}

	count, err := enforcer.Revoke(t.Context(), subject)
	require.ErrorIs(t, err, rec.killErr)
	assert.Zero(t, count)
	assert.Len(t, sessions.Lookup(subject), 1, "the client is still connected")

	rec.killErr = nil

	count, err = enforcer.Revoke(t.Context(), subject)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Equal(t, []string{"refresh 1", "kill 1", "refresh 1", "kill 1"}, rec.recorded())
}

func TestRevokeKillsEvenIfRefreshStateFails(t *testing.T) {
	t.Parallel()

	enforcer, _, rec, _ := newEnforcer(t, true)
	rec.refreshErr = errors.New("token store failed")

	count, err := enforcer.Revoke(t.Context(), sessionregistry.Identity{Issuer: issuer, SessionID: "sid-1"})
	require.ErrorIs(t, err, rec.refreshErr)
	assert.Zero(t, count)
	assert.Equal(t, []string{"refresh 1", "kill 1"}, rec.recorded())
}

func TestRevokeWithoutSubject(t *testing.T) {
	t.Parallel()

	enforcer, _, rec, _ := newEnforcer(t, true)

	_, err := enforcer.Revoke(t.Context(), sessionregistry.Identity{})
	require.Error(t, err)
	assert.Empty(t, rec.recorded())
}
