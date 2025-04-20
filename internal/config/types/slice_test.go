package types_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSliceUnmarshalText(t *testing.T) {
	t.Parallel()

	slice := types.StringSlice{}

	require.NoError(t, slice.UnmarshalText([]byte("a,b,c,d")))

	assert.Equal(t, types.StringSlice{"a", "b", "c", "d"}, slice)
}

func TestSliceMarshalText(t *testing.T) {
	t.Parallel()

	slice, err := types.StringSlice{"a", "b", "c", "d"}.MarshalText()

	require.NoError(t, err)

	assert.Equal(t, []byte("a,b,c,d"), slice)
}

func TestSliceUnmarshalJSON(t *testing.T) {
	t.Parallel()

	slice := types.StringSlice{}

	require.NoError(t, json.NewDecoder(strings.NewReader(`["a","b","c","d"]`)).Decode(&slice))

	assert.Equal(t, types.StringSlice{"a", "b", "c", "d"}, slice)
}

func TestSliceUnmarshalYAML(t *testing.T) {
	t.Parallel()

	slice := types.StringSlice{}

	require.NoError(t, yaml.NewDecoder(strings.NewReader("- a\n- b\n- c\n- d\n"), yaml.UseJSONUnmarshaler()).Decode(&slice))

	assert.Equal(t, types.StringSlice{"a", "b", "c", "d"}, slice)
}
