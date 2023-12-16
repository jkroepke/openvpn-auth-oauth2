package config

import (
	"strings"
)

type StringSlice []string

// MarshalText implements [encoding.TextMarshaler] interface for StringSlice
//
//goland:noinspection GoMixedReceiverTypes
func (stringSlice StringSlice) MarshalText() ([]byte, error) {
	return []byte(strings.Join(stringSlice, ",")), nil
}

// UnmarshalText implements the [encoding.TextUnmarshaler] interface for StringSlice
//
//goland:noinspection GoMixedReceiverTypes
func (stringSlice *StringSlice) UnmarshalText(text []byte) error {
	*stringSlice = strings.Split(string(text), ",")

	return nil
}
