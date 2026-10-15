package sessionregistry_test

import (
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/sessionregistry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const issuer = "https://idp.example.com"

func alice() sessionregistry.Identity {
	return sessionregistry.Identity{Issuer: issuer, Subject: "alice-sub", SessionID: "sid-1", Email: "alice@example.com"}
}

func TestIdentityIsZero(t *testing.T) {
	t.Parallel()

	assert.True(t, sessionregistry.Identity{}.IsZero())
	assert.False(t, sessionregistry.Identity{Email: "alice@example.com"}.IsZero())
}

func TestIdentityMerge(t *testing.T) {
	t.Parallel()

	fresh := sessionregistry.Identity{Issuer: issuer, Subject: "alice-sub"}
	stored := sessionregistry.Identity{Issuer: "https://old.example.com", SessionID: "sid-1", Email: "alice@example.com"}

	assert.Equal(t, sessionregistry.Identity{
		Issuer:    issuer,
		Subject:   "alice-sub",
		SessionID: "sid-1",
		Email:     "alice@example.com",
	}, fresh.Merge(stored))
}

func TestLookup(t *testing.T) {
	t.Parallel()

	bob := sessionregistry.Identity{Issuer: issuer, Subject: "bob-sub", SessionID: "sid-2", Email: "bob@example.com"}
	aliceSecondSession := alice()
	aliceSecondSession.SessionID = "sid-3"

	registry := sessionregistry.New()
	registry.Add(sessionregistry.Entry{CID: 3, Identity: aliceSecondSession, Username: "alice"})
	registry.Add(sessionregistry.Entry{CID: 1, Identity: alice(), Username: "alice"})
	registry.Add(sessionregistry.Entry{CID: 2, Identity: bob, Username: "bob"})

	for _, tc := range []struct {
		name  string
		query sessionregistry.Identity
		cids  []uint64
	}{
		{name: "iss and sub", query: sessionregistry.Identity{Issuer: issuer, Subject: "alice-sub"}, cids: []uint64{1, 3}},
		{name: "iss and sid", query: sessionregistry.Identity{Issuer: issuer, SessionID: "sid-1"}, cids: []uint64{1}},
		{name: "iss, sub and sid", query: sessionregistry.Identity{Issuer: issuer, Subject: "alice-sub", SessionID: "sid-3"}, cids: []uint64{3}},
		{name: "email", query: sessionregistry.Identity{Email: "bob@example.com"}, cids: []uint64{2}},
		{name: "other issuer", query: sessionregistry.Identity{Issuer: "https://other.example.com", Subject: "alice-sub"}},
		{name: "sub of another user with sid", query: sessionregistry.Identity{Issuer: issuer, Subject: "bob-sub", SessionID: "sid-1"}},
		{name: "empty query", query: sessionregistry.Identity{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			entries := registry.Lookup(tc.query)
			cids := make([]uint64, 0, len(entries))

			for _, entry := range entries {
				assert.True(t, entry.Connected)

				cids = append(cids, entry.CID)
			}

			assert.True(t, slices.Equal(tc.cids, cids), "expected %v, got %v", tc.cids, cids)
		})
	}
}

func TestAddReplacesEntryWithSameCID(t *testing.T) {
	t.Parallel()

	registry := sessionregistry.New()
	registry.Add(sessionregistry.Entry{CID: 1, Identity: alice(), Username: "alice"})

	reauthenticated := alice()
	reauthenticated.SessionID = "sid-2"
	registry.Add(sessionregistry.Entry{CID: 1, Identity: reauthenticated, Username: "alice"})

	assert.Equal(t, 1, registry.Len())
	assert.Empty(t, registry.Lookup(sessionregistry.Identity{Issuer: issuer, SessionID: "sid-1"}))
	assert.Len(t, registry.Lookup(sessionregistry.Identity{Issuer: issuer, SessionID: "sid-2"}), 1)
}

func TestDisconnect(t *testing.T) {
	t.Parallel()

	t.Run("without retention", func(t *testing.T) {
		t.Parallel()

		registry := sessionregistry.New()
		registry.Add(sessionregistry.Entry{CID: 1, OpenVPNSessionID: "ovpn-1", Identity: alice()})

		entry, ok := registry.Disconnect(1, 0)
		require.True(t, ok)
		assert.Equal(t, uint64(1), entry.CID)
		assert.Equal(t, 0, registry.Len())
		assert.Empty(t, registry.Lookup(alice()))
	})

	t.Run("without session id", func(t *testing.T) {
		t.Parallel()

		registry := sessionregistry.New()
		registry.Add(sessionregistry.Entry{CID: 1, Identity: alice()})

		_, ok := registry.Disconnect(1, time.Hour)
		require.True(t, ok)
		assert.Equal(t, 0, registry.Len())
	})

	t.Run("unknown cid", func(t *testing.T) {
		t.Parallel()

		registry := sessionregistry.New()
		registry.Add(sessionregistry.Entry{CID: 1, Identity: alice()})

		_, ok := registry.Disconnect(2, time.Hour)
		assert.False(t, ok)
		assert.Equal(t, 1, registry.Len())
	})
}

func TestDormantEntry(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		registry := sessionregistry.New()
		authenticatedAt := time.Now()
		registry.Add(sessionregistry.Entry{
			CID: 1, OpenVPNSessionID: "ovpn-1", Identity: alice(), Username: "alice", AuthenticatedAt: authenticatedAt,
		})

		_, ok := registry.Disconnect(1, time.Hour)
		require.True(t, ok)

		assert.Equal(t, []sessionregistry.Entry{{
			AuthenticatedAt:  authenticatedAt,
			Identity:         alice(),
			OpenVPNSessionID: "ovpn-1",
			Username:         "alice",
		}}, registry.Lookup(sessionregistry.Identity{Issuer: issuer, Subject: "alice-sub"}))

		time.Sleep(time.Hour)

		assert.Empty(t, registry.Lookup(alice()))
		assert.Equal(t, 0, registry.Len())
	})
}

func TestReconnectDropsDormantEntry(t *testing.T) {
	t.Parallel()

	registry := sessionregistry.New()
	registry.Add(sessionregistry.Entry{CID: 1, OpenVPNSessionID: "ovpn-1", Identity: alice()})
	_, ok := registry.Disconnect(1, time.Hour)
	require.True(t, ok)

	registry.Add(sessionregistry.Entry{CID: 7, OpenVPNSessionID: "ovpn-1", Identity: alice()})

	entries := registry.Lookup(alice())
	require.Len(t, entries, 1)
	assert.True(t, entries[0].Connected)
	assert.Equal(t, uint64(7), entries[0].CID)
	assert.Equal(t, 1, registry.Len())
}

func TestLookupOrdersConnectedBeforeDormant(t *testing.T) {
	t.Parallel()

	registry := sessionregistry.New()
	registry.Add(sessionregistry.Entry{CID: 1, OpenVPNSessionID: "ovpn-b", Identity: alice()})
	registry.Add(sessionregistry.Entry{CID: 2, OpenVPNSessionID: "ovpn-a", Identity: alice()})
	registry.Add(sessionregistry.Entry{CID: 3, OpenVPNSessionID: "ovpn-c", Identity: alice()})
	_, _ = registry.Disconnect(1, time.Hour)
	_, _ = registry.Disconnect(2, time.Hour)

	entries := registry.Lookup(alice())
	require.Len(t, entries, 3)
	assert.Equal(t, uint64(3), entries[0].CID)
	assert.True(t, entries[0].Connected)
	assert.Equal(t, "ovpn-a", entries[1].OpenVPNSessionID)
	assert.False(t, entries[1].Connected)
	assert.Equal(t, "ovpn-b", entries[2].OpenVPNSessionID)
}

func TestConcurrentAccess(t *testing.T) {
	t.Parallel()

	registry := sessionregistry.New()

	var wg sync.WaitGroup

	for cid := range uint64(32) {
		wg.Go(func() {
			registry.Add(sessionregistry.Entry{CID: cid, OpenVPNSessionID: "ovpn", Identity: alice()})
			_ = registry.Lookup(alice())
			_, _ = registry.Disconnect(cid, time.Minute)
		})
	}

	wg.Wait()

	assert.LessOrEqual(t, registry.Len(), 1)
}

func TestRemove(t *testing.T) {
	t.Parallel()

	registry := sessionregistry.New()
	registry.Add(sessionregistry.Entry{CID: 1, Identity: alice()})
	registry.Add(sessionregistry.Entry{CID: 2, OpenVPNSessionID: "ovpn-2", Identity: alice()})
	_, _ = registry.Disconnect(2, time.Hour)

	entries := registry.Lookup(alice())
	require.Len(t, entries, 2)

	for _, entry := range entries {
		assert.True(t, registry.Remove(entry))
		assert.False(t, registry.Remove(entry))
	}

	assert.Equal(t, 0, registry.Len())
}

func TestLookupEmailIsCaseInsensitive(t *testing.T) {
	t.Parallel()

	registry := sessionregistry.New()
	registry.Add(sessionregistry.Entry{CID: 1, Identity: alice()})

	assert.Len(t, registry.Lookup(sessionregistry.Identity{Email: "Alice@Example.COM"}), 1)
}
