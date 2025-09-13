package types

import (
	"bytes"
	"encoding/json"
	"regexp"
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

type RegexpSlice []*regexp.Regexp

// String returns the string representation of the [RegexpSlice].
//
//goland:noinspection GoMixedReceiverTypes
func (s RegexpSlice) String() string {
	stringList := make([]string, 0, len(s))
	for _, r := range s {
		stringList = append(stringList, r.String())
	}

	return strings.Join(stringList, ",")
}

// MarshalText implements [encoding.TextMarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (s RegexpSlice) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (s *RegexpSlice) UnmarshalText(text []byte) error {
	stringList := strings.Split(string(text), ",")
	regexList := make([]*regexp.Regexp, 0, len(stringList))
	for _, str := range stringList {
		r, err := regexp.Compile(str)
		if err != nil {
			return err
		}

		regexList = append(regexList, r)
	}

	*s = regexList

	return nil
}

// UnmarshalJSON implements the [json.Unmarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (s *RegexpSlice) UnmarshalJSON(jsonBytes []byte) error {
	var stringList []string

	err := json.NewDecoder(bytes.NewReader(jsonBytes)).Decode(&stringList)

	regexList := make([]*regexp.Regexp, 0, len(stringList))
	for _, str := range stringList {
		r, err := regexp.Compile(str)
		if err != nil {
			return err
		}

		regexList = append(regexList, r)
	}

	*s = regexList

	//nolint:wrapcheck
	return err
}
