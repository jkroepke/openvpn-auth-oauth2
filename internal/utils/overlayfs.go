package utils

import "io/fs"

type OverlayFS struct {
	root    fs.FS
	overlay fs.FS
}

// NewOverlayFS creates a filesystem that overlays the provided overlay over the
// base root filesystem. Files present in the overlay take precedence over files
// in the root.
func NewOverlayFS(root, over fs.FS) *OverlayFS { return &OverlayFS{root, over} }

func (f *OverlayFS) Open(name string) (fs.File, error) {
	fi, err := fs.Stat(f.overlay, name)
	if err == nil && !fi.IsDir() {
		if f, err := f.overlay.Open(name); err == nil {
			return f, nil
		}
	}

	return f.root.Open(name) //nolint:wrapcheck
}
