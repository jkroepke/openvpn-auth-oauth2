package openvpn

import (
	"errors"
)

var (
	ErrTimeout                              = errors.New("timeout")
	ErrEmptyResponse                        = errors.New("empty response")
	ErrUnknownProtocol                      = errors.New("unknown protocol")
	ErrInvalidPassword                      = errors.New("invalid password")
	ErrErrorResponse                        = errors.New("error response")
	ErrConnectionTerminated                 = errors.New("openvpn management interface connection terminated")
	ErrUnknownClientReason                  = errors.New("unknown client reason")
	ErrUnexpectedResponseFromVersionCommand = errors.New("unexpected response from version command")
	ErrRequireManagementInterfaceVersion5   = errors.New("openvpn-auth-oauth2 requires OpenVPN management interface version 5 or higher")
	ErrEnforceUniqueUserUnsupported         = errors.New(
		"openvpn.enforce-unique-user requires a direct OpenVPN management interface; the OpenVPN plugin shim is not supported",
	)
	ErrClientSessionStateInvalidOrExpired = errors.New(ReasonStateExpiredOrInvalid)
)

const (
	ReasonStateExpiredOrInvalid = "client session state invalid or expired"
)
