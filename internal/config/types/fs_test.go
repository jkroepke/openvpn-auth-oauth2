package types_test

import (
	"os"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/ui/assets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//nolint:exhaustruct
func TestIsFSEmpty(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expect, tt.fs.IsEmpty())
		})
	}
}

func TestFSUnmarshalText(t *testing.T) {
	t.Parallel()

	dirFS := types.FS{}

	require.NoError(t, dirFS.UnmarshalText([]byte(".")))

	assert.Equal(t, os.DirFS("."), dirFS)
}

func TestFSMarshalText(t *testing.T) {
	t.Parallel()

	dirFS, err := types.NewFS(".")
	require.NoError(t, err)

	path, err := dirFS.MarshalText()
	require.NoError(t, err)

	assert.Equal(t, []byte("."), path)
}
