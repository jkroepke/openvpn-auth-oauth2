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

//nolint:gochecknoglobals
var sessionStateMap = map[string]string{
	"Empty":                  SessionStateEmpty,
	"Initial":                SessionStateInitial,
	"Authenticated":          SessionStateAuthenticated,
	"Expired":                SessionStateExpired,
	"Invalid":                SessionStateInvalid,
	"AuthenticatedEmptyUser": SessionStateAuthenticatedEmptyUser,
	"ExpiredEmptyUser":       SessionStateExpiredEmptyUser,
}

//nolint:gochecknoglobals
var sessionStateReverseMap = map[string]string{
	SessionStateEmpty:                  "Empty",
	SessionStateInitial:                "Initial",
	SessionStateAuthenticated:          "Authenticated",
	SessionStateExpired:                "Expired",
	SessionStateInvalid:                "Invalid",
	SessionStateAuthenticatedEmptyUser: "AuthenticatedEmptyUser",
	SessionStateExpiredEmptyUser:       "ExpiredEmptyUser",
}

// decodeSessionState returns the string representation of the session state.
func decodeSessionState(s string) string {
	if v, ok := sessionStateReverseMap[s]; ok {
		return v
	}

	return ""
}

// encodeSessionState returns the compact representation of the session state.

func encodeSessionState(s string) string {
	if v, ok := sessionStateMap[s]; ok {
		return v
	}

	return SessionNoState
}
