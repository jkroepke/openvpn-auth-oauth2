package connection

import (
	"errors"
)

var (
	ErrEmptyClientReasons     = errors.New("empty client reason")
	ErrInvalidMessage         = errors.New("message invalid")
	ErrParseErrorClientReason = errors.New("unable to parse client reason from message")
)
