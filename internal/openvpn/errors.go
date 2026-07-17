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
	ErrKillDuplicateUsernameUnsupported     = errors.New(
		"duplicate username replacement requires an OpenVPN management interface with client-kill support; " +
			"set openvpn.kill-duplicate-username=false when using openvpn-auth-oauth2 as a management plugin",
	)
	ErrClientSessionStateInvalidOrExpired = errors.New(ReasonStateExpiredOrInvalid)
)

const (
	ReasonStateExpiredOrInvalid = "client session state invalid or expired"
)
