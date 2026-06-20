package types_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/ui/assets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFS(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		input string
		err   string
	}{
		{
			"empty",
			"",
			"open :",
		},
		{
			"dir",
			".",
			"",
		},
		{
			"invalid",
			"...",
			"error open \"...\":",
		},
		{
			"not found",
			"a",
			"error open \"a\":",
		},
		{
			"file",
			"../../../README.md",
			"not a directory",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := types.NewFS(tc.input)
			if tc.err == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.err)
			}
		})
	}
}

//nolint:exhaustruct
func TestIsFSEmpty(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		fs     *types.FS
		expect bool
	}{
		{
			"nil",
			nil,
			true,
		},
		{
			"empty",
			&types.FS{},
			true,
		},
		{
			"non-empty",
			&types.FS{FS: assets.FS},
			false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expect, tc.fs.IsEmpty())
		})
	}
}

func TestFSUnmarshalText(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		input string
		err   string
	}{
		{
			"empty",
			"",
			"open :",
		},
		{
			"dir",
			".",
			"",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			dirFS := types.FS{}

			err := dirFS.UnmarshalText([]byte(tc.input))
			if tc.err == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.err)
			}
		})
	}
}

func TestFSPreventsPathTraversal(t *testing.T) {
	t.Parallel()

	parentDir := t.TempDir()
	rootDir := filepath.Join(parentDir, "root")
	require.NoError(t, os.Mkdir(rootDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(parentDir, "outside.conf"), []byte("outside"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "profile ä !.conf"), []byte("inside"), 0o600))

	rootedFS, err := types.NewFS(rootDir)
	require.NoError(t, err)
	validFile, err := rootedFS.Open("profile ä !.conf")
	require.NoError(t, err)
	require.NoError(t, validFile.Close())

	_, err = rootedFS.Open("../outside.conf")
	require.Error(t, err)

	if runtime.GOOS == "windows" {
		return
	}

	require.NoError(t, os.Symlink(filepath.Join(parentDir, "outside.conf"), filepath.Join(rootDir, "link.conf")))

	_, err = rootedFS.Open("link.conf")
	require.Error(t, err)
}

func TestFSMarshalText(t *testing.T) {
	t.Parallel()

	dirFS, err := types.NewFS(".")
	require.NoError(t, err)

	path, err := dirFS.MarshalText()
	require.NoError(t, err)

	assert.Equal(t, []byte("."), path)
}
