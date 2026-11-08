package httphandler

import (
	"errors"
	"io/fs"
)

// overlayFS serves files from upper and falls back to lower for files that do
// not exist in upper. It lets http.assets-path override single embedded assets
// without copying all of them. Directories are reported as missing, so
// [net/http.FileServerFS] never renders a directory listing.
type overlayFS struct {
	upper fs.FS
	lower fs.FS
}

// Open opens name from upper, or from lower if upper does not contain name.
// Errors other than [fs.ErrNotExist] are returned without falling back.
func (o overlayFS) Open(name string) (fs.File, error) {
	file, err := o.upper.Open(name)
	if errors.Is(err, fs.ErrNotExist) {
		file, err = o.lower.Open(name)
	}

	if err != nil {
		return nil, err //nolint:wrapcheck
	}

	info, err := file.Stat()
	if err != nil {
		_ = file.Close()

		return nil, err //nolint:wrapcheck
	}

	if info.IsDir() {
		_ = file.Close()

		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}

	return file, nil
}
