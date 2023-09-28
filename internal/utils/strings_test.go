package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStringConcat(t *testing.T) {
	assert.Equal(t, "aabbcc", StringConcat("aa", "b", "b", "cc"))
}
