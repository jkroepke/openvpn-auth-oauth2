package types

import (
	"errors"
)

var (
	ErrInvalidClaimType = errors.New("invalid claim type")
	ErrNonExistsClaim   = errors.New("claim does not exist")
)
