package openvpn

import (
	"errors"
)

var (
	ErrTimeout              = errors.New("timeout")
	ErrEmptyResponse        = errors.New("empty response")
	ErrUnknownProtocol      = errors.New("unknown protocol")
	ErrInvalidPassword      = errors.New("invalid password")
	ErrErrorResponse        = errors.New("error response")
	ErrConnectionTerminated = errors.New("OpenVPN management interface connection terminated")
)
