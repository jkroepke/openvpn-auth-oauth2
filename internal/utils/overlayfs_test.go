package utils_test

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOverlayFS(t *testing.T) {
	baseFS := fstest.MapFS{
		"base": &fstest.MapFile{
			Data: []byte("base"),
		},
		"overlay": &fstest.MapFile{
			Data: []byte("base"),
		},
	}
	overlayFS := fstest.MapFS{
		"overlay": &fstest.MapFile{
			Data: []byte("overlay"),
		},
	}

	ofs := utils.NewOverlayFS(baseFS, overlayFS)

	content, err := fs.ReadFile(ofs, "overlay")
	require.NoError(t, err)
	assert.Equal(t, []byte("overlay"), content)

	content, err = fs.ReadFile(ofs, "base")
	require.NoError(t, err)
	assert.Equal(t, []byte("base"), content)

	content, err = fs.ReadFile(ofs, "nonexistent")
	require.Error(t, err)
}
