package types

import (
	"errors"
)

var (
	ErrNoIDToken        = errors.New("no id_token provided")
	ErrInvalidClaimType = errors.New("invalid claim type")
)
