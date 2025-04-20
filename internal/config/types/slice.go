package types

import (
	"bytes"
	"encoding/json"
	"strings"
)

type StringSlice []string

// String returns the string representation of the URL.
//
//goland:noinspection GoMixedReceiverTypes
func (s StringSlice) String() string {
	return strings.Join(s, ",")
}

// MarshalText implements [encoding.TextMarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (s StringSlice) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (s *StringSlice) UnmarshalText(text []byte) error {
	*s = strings.Split(string(text), ",")

	return nil
}

// UnmarshalJSON implements the [json.Unmarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (s *StringSlice) UnmarshalJSON(jsonBytes []byte) error {
	var slice []string

	err := json.NewDecoder(bytes.NewReader(jsonBytes)).Decode(&slice)

	*s = slice

	//nolint:wrapcheck
	return err
}
