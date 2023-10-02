package generic

import "errors"

var (
	ErrMismatch             = errors.New("mismatch")
	ErrMissingClaim         = errors.New("missing claim")
	ErrMissingRequiredRole  = errors.New("missing required role")
	ErrMissingRequiredGroup = errors.New("missing required group")
)
