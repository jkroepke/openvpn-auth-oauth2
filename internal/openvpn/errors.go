package openvpn

import (
	"errors"
	"fmt"
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

// ManagementCommandError reports a rejected OpenVPN management command.
type ManagementCommandError struct {
	Command  string
	Response string
}

func (e *ManagementCommandError) Error() string {
	return fmt.Sprintf("command error %q: %s", e.Command, e.Response)
}

func (e *ManagementCommandError) Unwrap() error {
	return ErrErrorResponse
}
