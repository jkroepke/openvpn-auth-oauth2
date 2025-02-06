package config

import (
	"bytes"
	"encoding/json"
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
func (s Secret) String() string {
	return string(s)
}

// MarshalText implements [encoding.TextMarshaler] interface for Secret
//
//goland:noinspection GoMixedReceiverTypes
func (s Secret) MarshalText() ([]byte, error) {
	return []byte(s), nil
}

// UnmarshalText implements the [encoding.TextUnmarshaler] interface for Secret
//
//goland:noinspection GoMixedReceiverTypes
func (s *Secret) UnmarshalText(text []byte) error {
	stringText := string(text)

	switch {
	case strings.HasPrefix(stringText, "file://"):
		filePath := os.ExpandEnv(strings.TrimPrefix(stringText, "file://"))

		body, err := os.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("unable read secret %s: %w", filePath, err)
		}

		body = bytes.TrimSpace(body)

		*s = Secret(body)
	default:
		*s = Secret(stringText)
	}

	return nil
}

//goland:noinspection GoMixedReceiverTypes
func (s Secret) MarshalJSON() ([]byte, error) {
	if len(s) == 0 {
		return json.Marshal("")
	}

	return json.Marshal("***")
}
