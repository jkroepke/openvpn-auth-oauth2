package types_test

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestRegexpSliceUnmarshalText(t *testing.T) {
	t.Parallel()

	slice := types.RegexpSlice{}

	require.NoError(t, slice.UnmarshalText([]byte("a,b,c,d")))

	//goland:noinspection RegExpUnnecessaryNonCapturingGroup
	assert.Equal(t, types.RegexpSlice{regexp.MustCompile("^(?:a)$"), regexp.MustCompile("^(?:b)$"), regexp.MustCompile("^(?:c)$"), regexp.MustCompile("^(?:d)$")}, slice)
}

func TestRegexpSliceUnmarshalTextError(t *testing.T) {
	t.Parallel()

	slice := types.RegexpSlice{}

	require.EqualError(t, slice.UnmarshalText([]byte("^(a,b,c,d")), "error parsing regexp: missing closing ): `^(?:^(a)$`")
}

func TestRegexpSliceMarshalText(t *testing.T) {
	t.Parallel()

	slice, err := types.RegexpSlice{regexp.MustCompile("a"), regexp.MustCompile("b"), regexp.MustCompile("c"), regexp.MustCompile("d")}.MarshalText()

	require.NoError(t, err)

	assert.Equal(t, []byte("a,b,c,d"), slice)
}

func TestRegexpSliceUnmarshalJSON(t *testing.T) {
	t.Parallel()

	slice := types.RegexpSlice{}

	require.EqualError(t, json.NewDecoder(strings.NewReader(`["^(a","b","c","d"]`)).Decode(&slice), "error parsing regexp: missing closing ): `^(?:^(a)$`")
}

func TestRegexpSliceUnmarshalYAML(t *testing.T) {
	t.Parallel()

	slice := types.RegexpSlice{}

	require.EqualError(t, yaml.NewDecoder(strings.NewReader("- \"^(a\"\n- b\n- c\n- d\n")).Decode(&slice), "error parsing regexp: missing closing ): `^(?:^(a)$`")
}
