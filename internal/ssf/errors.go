package ssf

import (
	"errors"
)

// Error codes a receiver reports for a SET it could not accept (RFC 8935,
// section 2.3, also used in the setErrs member of an RFC 8936 poll request).
const (
	ErrorCodeInvalidRequest  = "invalid_request"
	ErrorCodeInvalidKey      = "invalid_key"
	ErrorCodeInvalidIssuer   = "invalid_issuer"
	ErrorCodeInvalidAudience = "invalid_audience"
)

var (
	// ErrReplay reports a SET whose jti was already processed.
	ErrReplay = errors.New("security event token was already processed")
	// ErrUnsupportedSubject reports a subject identifier the receiver cannot act on.
	ErrUnsupportedSubject = errors.New("unsupported subject")
)

// Error is a SET verification error. Code is the RFC 8935 error code to report
// to the transmitter.
type Error struct {
	err  error
	Code string
}

func newError(code string, err error) *Error {
	return &Error{Code: code, err: err}
}

// Error implements the error interface.
func (e *Error) Error() string {
	return e.Code + ": " + e.err.Error()
}

// Unwrap returns the underlying error.
func (e *Error) Unwrap() error {
	return e.err
}

// Description returns a human-readable description of the error for the
// description member of an RFC 8935 error.
func (e *Error) Description() string {
	return e.err.Error()
}
