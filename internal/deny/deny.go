// Package deny defines why an OpenVPN client authentication is denied.
//
// A [Reason] is the single source for everything derived from a denial: the
// reason text sent with the OpenVPN client-deny command, the HTTP status of the
// browser error page, and the log level. Each reason belongs to one of the two
// failure classes documented in AGENTS.md: rejected (authentication or
// authorization failure) or internal (infrastructure or processing failure).
//
// Reason texts are fixed strings. Never pass a technical error message to
// OpenVPN; log it and return a Reason instead.
package deny

import (
	"errors"
	"log/slog"
	"net/http"
)

// Reason classifies why an OpenVPN client is denied.
type Reason uint8

const (
	// ClientRejected is the generic authentication or authorization failure.
	ClientRejected Reason = iota + 1
	// SSONotSupported means the OpenVPN client lacks webauth SSO support.
	SSONotSupported
	// ReAuthenticationDisabled means the client requested a re-authentication,
	// but re-authentication is disabled.
	ReAuthenticationDisabled
	// SessionStateInvalid means the client session state is invalid or expired.
	SessionStateInvalid
	// InvalidClientConfig means no client configuration could be resolved for the user.
	InvalidClientConfig
	// InvalidProfileSelection means the user selected a profile they are not allowed to use.
	InvalidProfileSelection

	// InternalError is the generic infrastructure or internal processing failure.
	InternalError
	// UserDataUnavailable means the user data could not be fetched from the provider.
	UserDataUnavailable
	// ProfileSelectorUnavailable means the profile selector token could not be created or stored.
	ProfileSelectorUnavailable
	// ClientConfigUnavailable means the client configuration could not be loaded.
	ClientConfigUnavailable
	// AcceptFailed means the client could not be accepted on the management interface.
	AcceptFailed
)

type reasonInfo struct {
	text     string
	internal bool
}

// reasons maps each Reason to its client-deny text and failure class.
// Index zero is the fallback for unknown reasons.
//
//nolint:gochecknoglobals
var reasons = [...]reasonInfo{
	0:                          {"internal error", true},
	ClientRejected:             {"client rejected", false},
	SSONotSupported:            {"OpenVPN Client does not support SSO authentication via webauth", false},
	ReAuthenticationDisabled:   {"client re-authentication not enabled", false},
	SessionStateInvalid:        {"client session state invalid or expired", false},
	InvalidClientConfig:        {"invalid client config", false},
	InvalidProfileSelection:    {"invalid profile selection", false},
	InternalError:              {"internal error", true},
	UserDataUnavailable:        {"unable to fetch user data", true},
	ProfileSelectorUnavailable: {"unable to create profile selector", true},
	ClientConfigUnavailable:    {"client configuration not found", true},
	AcceptFailed:               {"authentication acceptance failed", true},
}

// String returns the reason text sent with the OpenVPN client-deny command.
func (r Reason) String() string {
	return r.entry().text
}

// Internal reports whether the reason belongs to the internal error class.
// Unknown reasons are internal.
func (r Reason) Internal() bool {
	return r.entry().internal
}

// HTTPStatus returns the status code of the browser error page.
func (r Reason) HTTPStatus() int {
	if r.Internal() {
		return http.StatusInternalServerError
	}

	return http.StatusForbidden
}

// LogLevel returns the level for logging the technical error behind the denial.
func (r Reason) LogLevel() slog.Level {
	if r.Internal() {
		return slog.LevelError
	}

	return slog.LevelWarn
}

func (r Reason) entry() reasonInfo {
	if int(r) >= len(reasons) {
		return reasons[0]
	}

	return reasons[r]
}

// Error attaches a [Reason] to a technical error.
type Error struct {
	Err    error
	Reason Reason
}

// Wrap returns err annotated with reason. It returns nil if err is nil.
func Wrap(reason Reason, err error) error {
	if err == nil {
		return nil
	}

	return &Error{Reason: reason, Err: err}
}

func (e *Error) Error() string {
	return e.Err.Error()
}

func (e *Error) Unwrap() error {
	return e.Err
}

// ReasonOf returns the reason attached to err by [Wrap], or fallback if err
// carries no reason.
func ReasonOf(err error, fallback Reason) Reason {
	if denyErr, ok := errors.AsType[*Error](err); ok {
		return denyErr.Reason
	}

	return fallback
}
