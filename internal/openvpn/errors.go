package openvpn

import (
	"errors"
)

var (
	ErrTimeout            = errors.New("timeout")
	ErrEmptyResponse      = errors.New("empty response")
	ErrEmptyClientReasons = errors.New("empty client reason")
	ErrInvalidMessage     = errors.New("message invalid")
	ErrUnknownProtocol    = errors.New("unknown protocol")
	ErrInvalidPassword    = errors.New("invalid password")
	ErrErrorResponse      = errors.New("error response")
)
