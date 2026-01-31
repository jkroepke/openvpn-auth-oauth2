package oauth2

import "errors"

var (
	ErrMismatch                     = errors.New("mismatch")
	ErrMissingClaim                 = errors.New("missing claim")
	ErrMissingRequiredRole          = errors.New("missing required role")
	ErrMissingRequiredGroup         = errors.New("missing required group")
	ErrMissingToken                 = errors.New("no tokens provided")
	ErrAuthAndTokenEndpointRequired = errors.New("both oauth2.endpoints.tokenUrl and oauth2.endpoints.authUrl are required")
	ErrNoRefreshToken               = errors.New("no refresh token received from provider")

	ErrCELValidationFailed = errors.New("CEL validation failed")

	ErrClientRejected = errors.New("client rejected")
)
