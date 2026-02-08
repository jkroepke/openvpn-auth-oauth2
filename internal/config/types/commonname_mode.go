package types

import (
	"fmt"
	"strings"
)

// OpenVPNCommonNameMode defines how common names are processed.
type OpenVPNCommonNameMode int

const (
	CommonNameModePlain OpenVPNCommonNameMode = iota
	CommonNameModeOmit
)

// CommonNameModeOmitValue is the value used when common name mode is omit.
const CommonNameModeOmitValue = "-"

// String returns the string representation of the common name mode.
//
//goland:noinspection GoMixedReceiverTypes
func (s OpenVPNCommonNameMode) String() string {
	text, err := s.MarshalText()
	if err != nil {
		panic(err)
	}

	return string(text)
}

// MarshalText implements the [encoding.TextMarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (s OpenVPNCommonNameMode) MarshalText() ([]byte, error) {
	switch s {
	case CommonNameModePlain:
		return []byte("plain"), nil
	case CommonNameModeOmit:
		return []byte("omit"), nil
	default:
		return nil, fmt.Errorf("unknown identifier %d", s)
	}
}

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (s *OpenVPNCommonNameMode) UnmarshalText(text []byte) error {
	config := strings.ToLower(string(text))
	switch config {
	case "plain":
		*s = CommonNameModePlain
	case "omit":
		*s = CommonNameModeOmit
	default:
		return fmt.Errorf("invalid value %s", config)
	}

	return nil
}
