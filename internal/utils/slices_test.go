package utils_test

import (
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/stretchr/testify/assert"
)

func TestCastToSlice(t *testing.T) {
	t.Parallel()

	stringSlice, err := utils.CastToSlice[string]([]any{"string1", "string2", "string3"})
	assert.NoError(t, err)
	assert.Equal(t, stringSlice, []string{"string1", "string2", "string3"})
}

func TestCastToSliceInvalidSlice(t *testing.T) {
	t.Parallel()

	_, err := utils.CastToSlice[string]("string")
	if assert.Error(t, err) {
		assert.Equal(t, "unable to cast input to []any", err.Error())
	}
}

func TestCastToSliceInvalidElement(t *testing.T) {
	t.Parallel()

	_, err := utils.CastToSlice[string]([]any{"string1", "string2", 0})
	if assert.Error(t, err) {
		assert.Equal(t, "unable to cast element", err.Error())
	}
}
