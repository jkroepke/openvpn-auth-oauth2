package config

import (
	"fmt"
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

	switch {
	case strings.HasPrefix(stringText, "file://"):
		filePath := os.ExpandEnv(strings.TrimPrefix(stringText, "file://"))

		body, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("unable read secret %s: %w", filePath, err)
		}

		*secret = Secret(body)
	default:
		*secret = Secret(stringText)
	}

	return nil
}
