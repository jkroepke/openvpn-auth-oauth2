package config

import (
	"bytes"
	"fmt"
	"os"
	"strings"
)

// Secret represents a secret value that can be a plain string or a file path.
// If the value starts with "file://", it is treated as a file path, and the secret value is read from the file.
// The "file://" syntax supports environment variables.
// For example, "file://$HOME/my_secret.txt" would read the secret from the "my_secret.txt" file in the user's home directory.
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

		body = bytes.TrimSpace(body)

		*secret = Secret(body)
	default:
		*secret = Secret(stringText)
	}

	return nil
}

//goland:noinspection GoMixedReceiverTypes
func (secret *Secret) MarshalJSON() ([]byte, error) {
	return []byte("***"), nil
}
