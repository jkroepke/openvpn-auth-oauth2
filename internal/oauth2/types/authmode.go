package types

// AuthMode identifies the stage that evaluates a CEL expression.
type AuthMode string

const (
	// AuthModeInteractive identifies the initial browser-based authentication.
	AuthModeInteractive AuthMode = "interactive"
	// AuthModeNonInteractive identifies refresh-token authentication.
	AuthModeNonInteractive AuthMode = "non-interactive"
)
