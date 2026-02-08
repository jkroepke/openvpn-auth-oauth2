package types

import (
	"fmt"
	"strings"

	"golang.org/x/oauth2"
)

// OAuth2AuthStyle wraps [oauth2.AuthStyle] to provide text marshaling.
type OAuth2AuthStyle oauth2.AuthStyle

// String returns the string representation of the auth style.
//
//goland:noinspection GoMixedReceiverTypes
func (s OAuth2AuthStyle) String() string {
	text, err := s.MarshalText()
	if err != nil {
		panic(err)
	}

	return string(text)
}

// AuthStyle converts the wrapper type to [oauth2.AuthStyle].
//
//goland:noinspection GoMixedReceiverTypes
func (s OAuth2AuthStyle) AuthStyle() oauth2.AuthStyle {
	return oauth2.AuthStyle(s)
}

// MarshalText implements the [encoding.TextMarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (s OAuth2AuthStyle) MarshalText() ([]byte, error) {
	switch s {
	case OAuth2AuthStyle(oauth2.AuthStyleAutoDetect):
		return []byte("AuthStyleAutoDetect"), nil
	case OAuth2AuthStyle(oauth2.AuthStyleInParams):
		return []byte("AuthStyleInParams"), nil
	case OAuth2AuthStyle(oauth2.AuthStyleInHeader):
		return []byte("AuthStyleInHeader"), nil
	default:
		return nil, fmt.Errorf("unknown auth-style: %d", s)
	}
}

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (s *OAuth2AuthStyle) UnmarshalText(text []byte) error {
	switch strings.ToLower(string(text)) {
	case "authstyleautodetect":
		*s = OAuth2AuthStyle(oauth2.AuthStyleAutoDetect)
	case "authstyleinparams":
		*s = OAuth2AuthStyle(oauth2.AuthStyleInParams)
	case "authstyleinheader":
		*s = OAuth2AuthStyle(oauth2.AuthStyleInHeader)
	default:
		return fmt.Errorf("unknown auth-style: %s", text)
	}

	return nil
}
