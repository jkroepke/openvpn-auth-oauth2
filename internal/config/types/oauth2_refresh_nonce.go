package types

import (
	"fmt"
	"strings"
)

// OAuth2RefreshNonce controls nonce behavior on refresh token requests.
type OAuth2RefreshNonce int

const (
	OAuth2RefreshNonceAuto OAuth2RefreshNonce = iota
	OAuth2RefreshNonceEmpty
	OAuth2RefreshNonceEqual
)

// String returns the string representation of the refresh nonce mode.
//
//goland:noinspection GoMixedReceiverTypes
func (s OAuth2RefreshNonce) String() string {
	text, err := s.MarshalText()
	if err != nil {
		panic(err)
	}

	return string(text)
}

// MarshalText implements the [encoding.TextMarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (s OAuth2RefreshNonce) MarshalText() ([]byte, error) {
	switch s {
	case OAuth2RefreshNonceAuto:
		return []byte("auto"), nil
	case OAuth2RefreshNonceEmpty:
		return []byte("empty"), nil
	case OAuth2RefreshNonceEqual:
		return []byte("equal"), nil
	default:
		return nil, fmt.Errorf("unknown refresh-nonce %d", s)
	}
}

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (s *OAuth2RefreshNonce) UnmarshalText(text []byte) error {
	config := strings.ToLower(string(text))
	switch config {
	case "auto":
		*s = OAuth2RefreshNonceAuto
	case "empty":
		*s = OAuth2RefreshNonceEmpty
	case "equal":
		*s = OAuth2RefreshNonceEqual
	default:
		return fmt.Errorf("invalid value %s", config)
	}

	return nil
}
