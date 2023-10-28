package utils_test

import (
	"net/url"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/utils"
	"github.com/stretchr/testify/assert"
)

//nolint:exhaustruct
func TestIsUrlEmpty(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name   string
		url    *url.URL
		expect bool
	}{
		{
			"nil",
			nil,
			true,
		},
		{
			"empty",
			&url.URL{},
			true,
		},
		{
			"non-empty",
			&url.URL{Scheme: "http", Host: "localhost"},
			false,
		},
	} {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expect, utils.IsURLEmpty(tt.url))
		})
	}
}
