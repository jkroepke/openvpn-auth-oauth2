package httphandler

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"
)

type errFS struct {
	err error
}

func (e errFS) Open(string) (fs.File, error) {
	return nil, e.err
}

func TestOverlayFS(t *testing.T) {
	t.Parallel()

	lower := fstest.MapFS{
		"lower.txt": &fstest.MapFile{Data: []byte("lower")},
		"both.txt":  &fstest.MapFile{Data: []byte("lower")},
	}
	upper := fstest.MapFS{
		"both.txt": &fstest.MapFile{Data: []byte("upper")},
	}

	ofs := overlayFS{upper: upper, lower: lower}

	content, err := fs.ReadFile(ofs, "both.txt")
	require.NoError(t, err)
	require.Equal(t, "upper", string(content))

	content, err = fs.ReadFile(ofs, "lower.txt")
	require.NoError(t, err)
	require.Equal(t, "lower", string(content))

	_, err = fs.ReadFile(ofs, "missing.txt")
	require.ErrorIs(t, err, fs.ErrNotExist)

	// Only a missing file falls back; other errors of upper are returned.
	ofs = overlayFS{upper: errFS{err: fs.ErrPermission}, lower: lower}

	_, err = ofs.Open("lower.txt")
	require.ErrorIs(t, err, fs.ErrPermission)
}
