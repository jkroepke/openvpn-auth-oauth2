package types_test

import (
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/v2/internal/config/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileModeMarshalText(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		mode     types.FileMode
		expected string
		err      bool
	}{
		{
			name:     "zero permissions",
			mode:     0,
			expected: "0000",
		},
		{
			name:     "owner and group permissions",
			mode:     0o660,
			expected: "0660",
		},
		{
			name:     "all permissions",
			mode:     0o777,
			expected: "0777",
		},
		{
			name: "non-permission bits",
			mode: 0o1000,
			err:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			text, err := tc.mode.MarshalText()
			if tc.err {
				require.ErrorContains(t, err, "only permission bits")

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, string(text))
		})
	}
}

func TestFileModeUnmarshalText(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		input    string
		expected types.FileMode
		err      bool
	}{
		{
			name:     "leading zero",
			input:    "0660",
			expected: 0o660,
		},
		{
			name:     "octal prefix",
			input:    "0o640",
			expected: 0o640,
		},
		{
			name:     "zero permissions",
			input:    "0000",
			expected: 0,
		},
		{
			name:  "missing prefix",
			input: "660",
			err:   true,
		},
		{
			name:  "decimal equivalent",
			input: "432",
			err:   true,
		},
		{
			name:  "invalid octal digit",
			input: "0668",
			err:   true,
		},
		{
			name:  "non-permission bits",
			input: "01000",
			err:   true,
		},
		{
			name:  "empty",
			input: "",
			err:   true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			actual := types.FileMode(0o600)

			err := actual.UnmarshalText([]byte(tc.input))
			if tc.err {
				require.ErrorContains(t, err, "invalid file mode")
				assert.Equal(t, types.FileMode(0o600), actual)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
