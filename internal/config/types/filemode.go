package types

import (
	"encoding"
	"fmt"
	"io/fs"
	"strconv"
	"strings"
)

var (
	_ encoding.TextMarshaler   = FileMode(0)
	_ encoding.TextUnmarshaler = (*FileMode)(nil)
)

// FileMode is a Unix permission mode represented in configuration using explicit octal notation.
type FileMode fs.FileMode

// MarshalText implements the [encoding.TextMarshaler] interface.
func (m FileMode) MarshalText() ([]byte, error) {
	if m > FileMode(fs.ModePerm) {
		return nil, fmt.Errorf("invalid file mode %04o: only permission bits up to 0777 are allowed", m)
	}

	return fmt.Appendf(nil, "%04o", m), nil
}

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
func (m *FileMode) UnmarshalText(text []byte) error {
	value := string(text)

	var digits string

	switch {
	case len(value) == 4 && strings.HasPrefix(value, "0"):
		digits = value[1:]
	case len(value) == 5 && strings.HasPrefix(value, "0o"):
		digits = value[2:]
	default:
		return fmt.Errorf("invalid file mode %q: use explicit octal notation such as 0660", value)
	}

	parsed, err := strconv.ParseUint(digits, 8, 9)
	if err != nil {
		return fmt.Errorf("invalid file mode %q: use explicit octal notation such as 0660: %w", value, err)
	}

	*m = FileMode(parsed)

	return nil
}
