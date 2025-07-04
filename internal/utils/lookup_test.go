package utils_test

import (
	"fmt"
	"os/user"
	"runtime"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/stretchr/testify/require"
)

func TestLookupGroup(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("skipping test on windows")
	}

	for _, tt := range []struct {
		name string
		want int
		err  error
	}{
		{"sys", 3, nil},
		{"1001", 1001, nil},
		{"-", 0, fmt.Errorf("error lookup group: %w", user.UnknownGroupError("-"))},
		{"", 0, fmt.Errorf("error lookup group: %w", user.UnknownGroupError(""))},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := utils.LookupGroup(tt.name)
			if tt.err != nil {
				require.Error(t, err)
				require.Equal(t, tt.err, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.want, got)
			}
		})
	}
}
