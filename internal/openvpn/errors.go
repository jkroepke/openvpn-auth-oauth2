package openvpn

import (
	"errors"
)

var (
	ErrTimeout                            = errors.New("timeout")
	ErrEmptyResponse                      = errors.New("empty response")
	ErrUnknownProtocol                    = errors.New("unknown protocol")
	ErrInvalidPassword                    = errors.New("invalid password")
	ErrErrorResponse                      = errors.New("error response")
	ErrConnectionTerminated               = errors.New("openvpn management interface connection terminated")
	ErrUnknownClientReason                = errors.New("unknown client reason")
	ErrClientSessionStateInvalidOrExpired = errors.New(ReasonStateExpiredOrInvalid)
)

const (
	ReasonStateExpiredOrInvalid = "client session state invalid or expired"
)
