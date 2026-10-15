// Package sessionregistry maps authenticated OpenVPN clients to the OIDC
// identity they logged in with, so a security event about a user or an OIDC
// session can be resolved to the OpenVPN clients it applies to.
//
// The registry holds two kinds of entries: one per connected client, keyed by
// the OpenVPN client ID (CID), and dormant entries keyed by the OpenVPN
// session ID. A dormant entry describes a disconnected client that can still
// reconnect without an interactive login (oauth2.refresh.use-session-id) and
// expires together with its stored refresh state.
package sessionregistry

import (
	"cmp"
	"slices"
	"strings"
	"sync"
	"time"
)

// Identity is the OIDC identity of an authenticated client.
type Identity struct {
	// Issuer is the iss claim of the ID token.
	Issuer string `json:"iss,omitempty"`
	// Subject is the sub claim of the ID token.
	Subject string `json:"sub,omitempty"`
	// SessionID is the sid claim of the ID token. It is empty when the
	// provider does not send it.
	SessionID string `json:"sid,omitempty"`
	// Email is the email claim of the ID token or the UserInfo response.
	Email string `json:"email,omitempty"`
}

// IsZero reports whether no field of the identity is set.
func (i Identity) IsZero() bool {
	return i == Identity{}
}

// Merge returns i with every empty field taken from fallback.
func (i Identity) Merge(fallback Identity) Identity {
	return Identity{
		Issuer:    cmp.Or(i.Issuer, fallback.Issuer),
		Subject:   cmp.Or(i.Subject, fallback.Subject),
		SessionID: cmp.Or(i.SessionID, fallback.SessionID),
		Email:     cmp.Or(i.Email, fallback.Email),
	}
}

// matches reports whether every non-empty field of query equals the field of i.
// Emails are compared case-insensitively. An empty query matches nothing.
func (i Identity) matches(query Identity) bool {
	if query.IsZero() {
		return false
	}

	return matchField(query.Issuer, i.Issuer) &&
		matchField(query.Subject, i.Subject) &&
		matchField(query.SessionID, i.SessionID) &&
		(query.Email == "" || strings.EqualFold(query.Email, i.Email))
}

func matchField(query, value string) bool {
	return query == "" || query == value
}

// Entry describes one authenticated OpenVPN client.
type Entry struct {
	// AuthenticatedAt is the time the client was accepted.
	AuthenticatedAt time.Time
	// Identity is the OIDC identity the client authenticated with.
	Identity Identity
	// OpenVPNSessionID is the OpenVPN auth-gen-token session ID. It is empty
	// unless OpenVPN runs with external auth tokens.
	OpenVPNSessionID string
	// Username is the OpenVPN username, for logs only.
	Username string
	// CID is the OpenVPN client ID. It is only meaningful while Connected.
	CID uint64
	// Connected is false for a dormant entry of a disconnected client.
	Connected bool
}

type dormantEntry struct {
	expiresAt time.Time
	entry     Entry
}

// Registry is a concurrency-safe in-memory session registry.
// The zero value is not usable; use [New].
type Registry struct {
	connected map[uint64]Entry
	dormant   map[string]dormantEntry
	mu        sync.Mutex
}

// New returns an empty [Registry].
func New() *Registry {
	return &Registry{
		connected: make(map[uint64]Entry),
		dormant:   make(map[string]dormantEntry),
	}
}

// Add records an accepted client. An entry with the same CID is replaced,
// and a dormant entry with the same OpenVPN session ID is dropped, because
// the session is connected again.
func (r *Registry) Add(entry Entry) {
	entry.Connected = true

	r.mu.Lock()
	defer r.mu.Unlock()

	r.pruneLocked(time.Now())

	if entry.OpenVPNSessionID != "" {
		delete(r.dormant, entry.OpenVPNSessionID)
	}

	r.connected[entry.CID] = entry
}

// Disconnect removes the entry of a disconnected client and returns it.
// If retain is positive and the entry has an OpenVPN session ID, a dormant
// entry is kept for retain, so the session can still be found while it can
// reconnect without an interactive login.
func (r *Registry) Disconnect(cid uint64, retain time.Duration) (Entry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	r.pruneLocked(now)

	entry, ok := r.connected[cid]
	if !ok {
		return Entry{}, false
	}

	delete(r.connected, cid)

	if retain > 0 && entry.OpenVPNSessionID != "" {
		dormant := entry
		dormant.Connected = false
		dormant.CID = 0

		r.dormant[entry.OpenVPNSessionID] = dormantEntry{entry: dormant, expiresAt: now.Add(retain)}
	}

	return entry, true
}

// Remove removes an entry returned by [Registry.Lookup]: a connected entry
// by its CID, a dormant entry by its OpenVPN session ID. It reports whether
// the entry was still present.
func (r *Registry) Remove(entry Entry) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if entry.Connected {
		_, ok := r.connected[entry.CID]
		delete(r.connected, entry.CID)

		return ok
	}

	_, ok := r.dormant[entry.OpenVPNSessionID]
	delete(r.dormant, entry.OpenVPNSessionID)

	return ok
}

// Lookup returns all connected and dormant entries whose identity matches
// every non-empty field of query. An empty query matches nothing.
// Connected entries come first, ordered by CID, then dormant entries,
// ordered by OpenVPN session ID.
func (r *Registry) Lookup(query Identity) []Entry {
	if query.IsZero() {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.pruneLocked(time.Now())

	var entries []Entry

	for _, entry := range r.connected {
		if entry.Identity.matches(query) {
			entries = append(entries, entry)
		}
	}

	for _, dormant := range r.dormant {
		if dormant.entry.Identity.matches(query) {
			entries = append(entries, dormant.entry)
		}
	}

	slices.SortFunc(entries, compareEntries)

	return entries
}

// Len returns the number of connected and dormant entries.
func (r *Registry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.pruneLocked(time.Now())

	return len(r.connected) + len(r.dormant)
}

// pruneLocked drops expired dormant entries. r.mu must be held.
func (r *Registry) pruneLocked(now time.Time) {
	for sessionID, dormant := range r.dormant {
		if !now.Before(dormant.expiresAt) {
			delete(r.dormant, sessionID)
		}
	}
}

func compareEntries(left, right Entry) int {
	if left.Connected != right.Connected {
		if left.Connected {
			return -1
		}

		return 1
	}

	return cmp.Or(
		cmp.Compare(left.CID, right.CID),
		cmp.Compare(left.OpenVPNSessionID, right.OpenVPNSessionID),
	)
}
