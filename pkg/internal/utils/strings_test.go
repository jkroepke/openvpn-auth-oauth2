package utils_test

import (
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/pkg/internal/utils"
	"github.com/stretchr/testify/assert"
)

func TestStringConcat(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "aabbcc", utils.StringConcat("aa", "b", "b", "cc"))
}
