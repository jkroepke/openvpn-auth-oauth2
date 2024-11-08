package state

const (
	SessionNoState                     = "0"
	SessionStateEmpty                  = "1"
	SessionStateInitial                = "2"
	SessionStateAuthenticated          = "3"
	SessionStateExpired                = "4"
	SessionStateInvalid                = "5"
	SessionStateAuthenticatedEmptyUser = "6"
	SessionStateExpiredEmptyUser       = "7"
)

// decodeSessionState returns the string representation of the session state.
func decodeSessionState(s string) string {
	switch s {
	case SessionStateEmpty:
		return "Empty"
	case SessionStateInitial:
		return "Initial"
	case SessionStateAuthenticated:
		return "Authenticated"
	case SessionStateExpired:
		return "Expired"
	case SessionStateInvalid:
		return "Invalid"
	case SessionStateAuthenticatedEmptyUser:
		return "AuthenticatedEmptyUser"
	case SessionStateExpiredEmptyUser:
		return "ExpiredEmptyUser"
	default:
		return ""
	}
}

// encodeSessionState returns the compact representation of the session state.
func encodeSessionState(s string) string {
	switch s {
	case "Empty":
		return SessionStateEmpty
	case "Initial":
		return SessionStateInitial
	case "Authenticated":
		return SessionStateAuthenticated
	case "Expired":
		return SessionStateExpired
	case "Invalid":
		return SessionStateInvalid
	case "AuthenticatedEmptyUser":
		return SessionStateAuthenticatedEmptyUser
	case "ExpiredEmptyUser":
		return SessionStateExpiredEmptyUser
	default:
		return SessionNoState
	}
}
