package config

import (
	"os"
	"strings"
)

type Secret string

// String reassembles the Secret into a valid string.
//
//goland:noinspection GoMixedReceiverTypes
func (secret Secret) String() string {
	return string(secret)
}

// MarshalText implements [encoding.TextMarshaler] interface for Secret
//
//goland:noinspection GoMixedReceiverTypes
func (secret Secret) MarshalText() ([]byte, error) {
	return []byte(secret), nil
}

// UnmarshalText implements the [encoding.TextUnmarshaler] interface for Secret
//
//goland:noinspection GoMixedReceiverTypes
func (secret *Secret) UnmarshalText(text []byte) error {
	stringText := string(text)
	if !strings.HasPrefix(stringText, "file://") {
		*secret = Secret(stringText)
		return nil
	}

	body, err := os.ReadFile(strings.TrimPrefix(stringText, "file://"))
	if err != nil {
		return err
	}

	*secret = Secret(body)

	return err
}
