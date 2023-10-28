package utils_test

import (
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCastToSlice(t *testing.T) {
	t.Parallel()

	stringSlice, err := utils.CastToSlice[string]([]any{"string1", "string2", "string3"})
	require.NoError(t, err)
	assert.Equal(t, []string{"string1", "string2", "string3"}, stringSlice)
}

func TestCastToSliceInvalidSlice(t *testing.T) {
	t.Parallel()

	_, err := utils.CastToSlice[string]("string")
	require.Error(t, err)
	assert.Equal(t, "unable to cast input to []any", err.Error())
}

func TestCastToSliceInvalidElement(t *testing.T) {
	t.Parallel()

	_, err := utils.CastToSlice[string]([]any{"string1", "string2", 0})
	require.Error(t, err)
	assert.Equal(t, "unable to cast element", err.Error())
}
