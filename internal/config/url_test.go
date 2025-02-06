package config_test

import (
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/stretchr/testify/assert"
)

//nolint:exhaustruct
func TestIsUrlEmpty(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name   string
		url    *config.URL
		expect bool
	}{
		{
			"nil",
			nil,
			true,
		},
		{
			"empty",
			&config.URL{},
			true,
		},
		{
			"non-empty",
			&config.URL{Scheme: "http", Host: "localhost"},
			false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expect, tt.url.IsEmpty())
		})
	}
}
