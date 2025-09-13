package types

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
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
	var stringList []string

	err := json.NewDecoder(bytes.NewReader(jsonBytes)).Decode(&stringList)
	if err != nil {
		//nolint:wrapcheck
		return err
	}

	*s = stringList

	return nil
}

// UnmarshalYAML implements the [yaml.Unmarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (s *StringSlice) UnmarshalYAML(data *yaml.Node) error {
	var stringList []string

	err := data.Decode(&stringList)
	if err != nil {
		//nolint:wrapcheck
		return err
	}

	*s = stringList

	return nil
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
	return s.fromSlice(strings.Split(string(text), ","))
}

// UnmarshalJSON implements the [json.Unmarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (s *RegexpSlice) UnmarshalJSON(jsonBytes []byte) error {
	var stringList []string

	err := json.NewDecoder(bytes.NewReader(jsonBytes)).Decode(&stringList)
	if err != nil {
		//nolint:wrapcheck
		return err
	}

	return s.fromSlice(stringList)
}

// UnmarshalYAML implements the [yaml.Unmarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (s *RegexpSlice) UnmarshalYAML(data *yaml.Node) error {
	var stringList []string

	err := data.Decode(&stringList)
	if err != nil {
		//nolint:wrapcheck
		return err
	}

	return s.fromSlice(stringList)
}

//goland:noinspection GoMixedReceiverTypes
func (s *RegexpSlice) fromSlice(stringList []string) error {
	regexList := make(RegexpSlice, 0, len(stringList))
	for _, str := range stringList {
		regexPattern, err := regexp.Compile(fmt.Sprintf("^(?:%s)$", str))
		if err != nil {
			//nolint:wrapcheck
			return err
		}

		regexList = append(regexList, regexPattern)
	}

	*s = regexList

	return nil
}
