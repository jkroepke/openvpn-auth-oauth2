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
	dirFS := NewRootFS(filePath)

	dir, err := dirFS.Open(".")
	if err != nil {
		return FS{}, fmt.Errorf("error open %q: %w", filePath, err)
	}

	dirState, err := dir.Stat()
	if err != nil {
		return FS{}, fmt.Errorf("error stat %q: %w", filePath, err)
	}

	if !dirState.IsDir() {
		return FS{}, fmt.Errorf("path %q is not a directory", filePath)
	}

	return dirFS, nil
}

// NewRootFS returns a file system rooted at filePath.
//
// Unlike [os.DirFS], the returned file system prevents symbolic links from
// escaping the root. Both implementations reject paths containing "." or
// ".." elements as required by [fs.ValidPath].
func NewRootFS(filePath string) FS {
	return FS{FS: rootFS(filePath), path: filePath}
}

type rootFS string

func (f rootFS) Open(name string) (fs.File, error) {
	root, err := os.OpenRoot(string(f))
	if err != nil {
		return nil, fmt.Errorf("open root %q: %w", f, err)
	}
	defer root.Close()

	return root.FS().Open(name) //nolint:wrapcheck
}

// IsEmpty checks if the template is empty.
//
//goland:noinspection GoMixedReceiverTypes
func (f *FS) IsEmpty() bool {
	return f == nil || f.FS == nil
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
