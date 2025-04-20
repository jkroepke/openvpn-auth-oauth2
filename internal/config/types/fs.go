package types

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
)

type FS struct {
	fs.FS
	path string
}

func NewFS(filePath string) (FS, error) {
	dirFS := os.DirFS(filePath)

	dir, err := dirFS.Open(".")
	if err != nil {
		return FS{}, fmt.Errorf("error open filesystem: %w", err)
	}

	dirState, err := dir.Stat()
	if err != nil {
		return FS{}, fmt.Errorf("error stat filesystem: %w", err)
	}

	if !dirState.IsDir() {
		return FS{}, fmt.Errorf("path %s is not a directory", filePath)
	}

	return FS{dirFS, filePath}, nil
}

// IsEmpty checks if the template is empty.
//
//goland:noinspection GoMixedReceiverTypes
func (f *FS) IsEmpty() bool {
	return f.FS == nil
}

// String returns the path of the template.
//
//goland:noinspection GoMixedReceiverTypes
func (f *FS) String() string {
	return f.path
}

// MarshalText implements the [encoding.TextMarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (f FS) MarshalText() ([]byte, error) {
	return []byte(f.String()), nil
}

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (f *FS) UnmarshalText(text []byte) error {
	dirFS, err := NewFS(string(text))
	if err != nil {
		return err
	}

	*f = dirFS

	return nil
}

// MarshalJSON implements the [json.Marshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (f *FS) MarshalJSON() ([]byte, error) {
	return json.Marshal(f.String()) //nolint:wrapcheck
}
