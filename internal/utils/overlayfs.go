package utils

import "io/fs"

type OverlayFS struct {
	fs   fs.FS
	over fs.FS
}

func NewOverlayFS(fs, over fs.FS) *OverlayFS { return &OverlayFS{fs, over} }

func (f *OverlayFS) Open(name string) (fs.File, error) {
	fi, err := fs.Stat(f.over, name)
	if err == nil && !fi.IsDir() {
		if f, err := f.over.Open(name); err == nil {
			return f, nil
		}
	}

	return f.fs.Open(name)
}
