// Package revocation ends the OpenVPN sessions of revoked OIDC sessions.
//
// A revocation, for example from a CAEP session-revoked event, is applied to
// every matching session in the session registry in this order:
//
//  1. The entry is removed from the registry, so the disconnect that follows
//     keeps no dormant entry for it.
//  2. Its stored refresh state is deleted, so a reconnecting client has to
//     log in interactively.
//  3. A connected client is terminated with client-kill.
//
// Deleting the refresh state before the kill ensures that a client
// reconnecting at any point lands in the interactive login, never in a
// silent re-authentication. The next login goes through the provider, which
// has already revoked the session itself, so no revocation list is kept.
package revocation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/metrics"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/sessionregistry"
	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/ssf"
)

// RefreshStateRevoker deletes the stored refresh state of a session.
// oauth2.Client implements it.
type RefreshStateRevoker interface {
	RevokeRefreshState(ctx context.Context, logger *slog.Logger, entry sessionregistry.Entry) error
}

// SessionKiller terminates a connected OpenVPN client. A client that is
// already gone must not be reported as an error. openvpn.Client implements
// it on the management interface.
type SessionKiller interface {
	KillClient(ctx context.Context, logger *slog.Logger, clientID uint64) error
}

// Enforcer applies revocations to the clients in a session registry.
type Enforcer struct {
	logger       *slog.Logger
	conf         *config.Config
	sessions     *sessionregistry.Registry
	refreshState RefreshStateRevoker
	killer       SessionKiller
	metrics      *metrics.Metrics
}

// New returns an [Enforcer]. appMetrics may be nil.
func New(
	logger *slog.Logger, conf *config.Config, sessions *sessionregistry.Registry,
	refreshState RefreshStateRevoker, killer SessionKiller, appMetrics *metrics.Metrics,
) *Enforcer {
	return &Enforcer{
		logger:       logger,
		conf:         conf,
		sessions:     sessions,
		refreshState: refreshState,
		killer:       killer,
		metrics:      appMetrics,
	}
}

// Revoke ends every OpenVPN session whose identity matches subject, like a
// [sessionregistry.Registry.Lookup] query, and returns how many it ended.
// A subject with a SessionID names one OIDC session (session level); without
// one, it names every session of the user (user level). User-level
// revocations are ignored when ssf.user-level-revocation is false.
//
// A session whose client could not be terminated stays in the registry, so
// the revocation can be applied again.
func (e *Enforcer) Revoke(ctx context.Context, subject sessionregistry.Identity) (int, error) {
	scope := metrics.RevocationScopeUser
	if subject.SessionID != "" {
		scope = metrics.RevocationScopeSession
	}

	logger := e.logger.With(
		slog.String("scope", scope),
		slog.String("subject_iss", subject.Issuer),
		slog.String("subject_sub", subject.Subject),
		slog.String("subject_sid", subject.SessionID),
	)

	if subject.IsZero() {
		return 0, errors.New("revocation has no subject")
	}

	if scope == metrics.RevocationScopeUser && !e.conf.SSF.UserLevelRevocation {
		logger.LogAttrs(ctx, slog.LevelInfo, "ignoring user-level revocation, because ssf.user-level-revocation is disabled")

		return 0, nil
	}

	matched, revoked, err := e.revokeMatching(ctx, logger, subject)
	if matched == 0 {
		logger.LogAttrs(ctx, slog.LevelDebug, "revocation matches no OpenVPN session")

		return 0, nil
	}

	e.metrics.SessionsRevoked(scope, revoked)

	return revoked, err
}

// maxLookups bounds how often [Enforcer.Revoke] looks up entries that
// changed while it ran.
const maxLookups = 3

// entryKey identifies a registry entry: a connected client by its CID, a
// dormant one by its OpenVPN session ID.
type entryKey struct {
	sessionID string
	cid       uint64
	connected bool
}

func keyOf(entry sessionregistry.Entry) entryKey {
	if entry.Connected {
		return entryKey{connected: true, cid: entry.CID}
	}

	return entryKey{sessionID: entry.OpenVPNSessionID}
}

// HandleEvent applies a verified SSF session-revoked event. It implements
// [ssf.Handler].
func (e *Enforcer) HandleEvent(ctx context.Context, event ssf.Event) (int, error) {
	return e.Revoke(ctx, sessionregistry.Identity{
		Issuer:    event.Subject.Issuer,
		Subject:   event.Subject.Subject,
		SessionID: event.Subject.SessionID,
		Email:     event.Subject.Email,
	})
}

// revokeMatching revokes every entry that matches subject and returns how
// many entries matched and how many were revoked.
func (e *Enforcer) revokeMatching(ctx context.Context, logger *slog.Logger, subject sessionregistry.Identity) (int, int, error) {
	var (
		errs      []error
		revoked   int
		attempted = make(map[entryKey]struct{})
	)

	// A client that disconnects while the revocation runs leaves a dormant
	// entry instead of its connected one, so look up again until every
	// matching entry was handled.
	for range maxLookups {
		var missed bool

		for _, entry := range e.sessions.Lookup(subject) {
			key := keyOf(entry)
			if _, ok := attempted[key]; ok {
				continue
			}

			attempted[key] = struct{}{}

			if !e.sessions.Remove(entry) {
				// A concurrent revocation handled it, or the client disconnected.
				missed = true

				continue
			}

			if err := e.revokeEntry(ctx, logger, entry); err != nil {
				errs = append(errs, err)

				continue
			}

			revoked++
		}

		if !missed {
			break
		}
	}

	return len(attempted), revoked, errors.Join(errs...)
}

func (e *Enforcer) revokeEntry(ctx context.Context, logger *slog.Logger, entry sessionregistry.Entry) error {
	logger = logger.With(
		slog.Uint64("cid", entry.CID),
		slog.String("session_id", entry.OpenVPNSessionID),
		slog.String("username", entry.Username),
		slog.Bool("connected", entry.Connected),
	)

	var refreshErr error

	if err := e.refreshState.RevokeRefreshState(ctx, logger, entry); err != nil {
		logger.LogAttrs(ctx, slog.LevelError, "unable to delete the refresh state of a revoked session", slog.Any("err", err))

		refreshErr = fmt.Errorf("delete refresh state: %w", err)
	}

	if entry.Connected {
		if err := e.killer.KillClient(ctx, logger, entry.CID); err != nil {
			logger.LogAttrs(ctx, slog.LevelError, "unable to terminate the OpenVPN session of a revoked session", slog.Any("err", err))
			e.sessions.Add(entry)

			return errors.Join(refreshErr, fmt.Errorf("terminate OpenVPN session: %w", err))
		}
	}

	if refreshErr != nil {
		return refreshErr
	}

	logger.LogAttrs(ctx, slog.LevelInfo, "revoked OpenVPN session")

	return nil
}
