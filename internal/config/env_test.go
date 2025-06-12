package config //nolint:testpackage

import (
	"net/url"
	"testing"
	"time"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/ui/assets"
	"github.com/stretchr/testify/require"
)

func TestLookupEnvOrDefault(t *testing.T) {
	for _, tc := range []struct {
		name         string
		input        string
		badInput     string
		defaultValue any
		expected     any
		panic        bool
	}{
		{
			name:         "string",
			defaultValue: "test",
			input:        "test2",
			expected:     "test2",
		},
		{
			name:         "bool",
			defaultValue: false,
			input:        "true",
			badInput:     "A",
			expected:     true,
		},
		{
			name:         "int",
			defaultValue: 1336,
			input:        "1337",
			badInput:     "A",
			expected:     1337,
		},
		{
			name:         "uint",
			defaultValue: uint(1336),
			input:        "1337",
			badInput:     "A",
			expected:     uint(1337),
		},
		{
			name:         "time.Duration",
			defaultValue: time.Minute,
			input:        "5s",
			badInput:     "A",
			expected:     5 * time.Second,
		},
		{
			name:         "TextUnmarshaler/FS",
			defaultValue: &types.FS{FS: assets.FS},
			input:        ".",
			badInput:     "...",
			expected: func() *types.FS {
				f, err := types.NewFS(".")
				require.NoError(t, err)

				return &f
			}(),
		},
		{
			name:         "TextUnmarshaler/Secret",
			defaultValue: types.Secret("hello world"),
			input:        "hello world",
			badInput:     "file://",
			expected:     types.Secret("hello world"),
		},
		{
			name:         "TextUnmarshaler/URL",
			defaultValue: types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
			input:        "http://google.com",
			badInput:     "://google.com",
			expected:     types.URL{URL: &url.URL{Scheme: "http", Host: "google.com"}},
		},
		{
			name:         "TextUnmarshaler/StringSlice",
			defaultValue: types.StringSlice{},
			input:        "a,b",
			badInput:     "",
			expected:     types.StringSlice{"a", "b"},
		},
		{
			name:         "TextUnmarshaler/types.Template",
			defaultValue: types.Template{},
			input:        "../../README.md",
			badInput:     "....",
			expected: func() types.Template {
				tmpl, err := types.NewTemplate("../../README.md")
				require.NoError(t, err)

				return tmpl
			}(),
		},
		{
			name:         "float64",
			defaultValue: float64(1336),
			input:        "1337",
			expected:     float64(1337),
		},
		{
			name:         "float32",
			defaultValue: float32(1336),
			input:        "1337",
			expected:     float32(1337),
			panic:        true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testFn := func() {
				require.Equal(t, tc.defaultValue, lookupEnvOrDefault("unset", tc.defaultValue))

				t.Setenv("CONFIG_SET", tc.input)
				require.Equal(t, tc.expected, lookupEnvOrDefault("set", tc.defaultValue))

				if tc.badInput != "" {
					t.Setenv("CONFIG_BAD", tc.badInput)
					require.Equal(t, tc.defaultValue, lookupEnvOrDefault("bad", tc.defaultValue))
				}
			}

			if tc.panic {
				require.Panics(t, testFn)
			} else {
				require.NotPanics(t, testFn)
			}
		})
	}
}
