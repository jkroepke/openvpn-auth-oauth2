package utils

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsUrlEmpty(t *testing.T) {
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
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expect, IsUrlEmpty(tt.url))
		})
	}
}
