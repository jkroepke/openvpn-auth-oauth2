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
