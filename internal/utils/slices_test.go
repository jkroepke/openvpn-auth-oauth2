package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCastToSlice(t *testing.T) {
	stringSlice := CastToSlice[string]([]any{"string1", "string2", "string3"})

	assert.Equal(t, stringSlice, []string{"string1", "string2", "string3"})
}
