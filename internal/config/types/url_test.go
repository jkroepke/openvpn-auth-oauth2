package types_test

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestURL(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		input string
		err   string
	}{
		{
			"empty",
			"",
			"empty URL",
		},
		{
			"invalid",
			"://",
			"missing protocol scheme",
		},
		{
			"valid",
			"https://example.com",
			"",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := types.NewURL(tc.input)
			if tc.err == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.err)
			}
		})
	}
}

//nolint:exhaustruct
func TestURLIsEmpty(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		url    *types.URL
		expect bool
	}{
		{
			"nil",
			nil,
			true,
		},
		{
			"empty",
			&types.URL{},
			true,
		},
		{
			"non-empty",
			&types.URL{URL: &url.URL{Scheme: "http", Host: "localhost"}},
			false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.expect, tc.url.IsEmpty())
		})
	}
}

func TestURLUnmarshalText(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		input string
		err   string
	}{
		{
			"empty",
			"",
			"empty URL",
		},
		{
			"invalid",
			"://",
			"missing protocol scheme",
		},
		{
			"valid",
			"https://example.com",
			"",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			actualURL := types.URL{}

			err := actualURL.UnmarshalText([]byte(tc.input))
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)

				return
			}

			require.NoError(t, err)

			expectedURL, err := types.NewURL(tc.input)
			require.NoError(t, err)

			require.Equal(t, expectedURL, actualURL)
		})
	}
}

func TestURLMarshalText(t *testing.T) {
	t.Parallel()

	actualURL, err := types.NewURL("https://example.com")
	require.NoError(t, err)

	urlBytes, err := actualURL.MarshalText()
	require.NoError(t, err)

	require.Equal(t, []byte("https://example.com"), urlBytes)
}

func TestURLUnmarshalJSON(t *testing.T) {
	t.Parallel()

	actualURL := types.URL{}
	require.NoError(t, json.NewDecoder(strings.NewReader(`"https://example.com"`)).Decode(&actualURL))

	expectedURL, err := types.NewURL("https://example.com")
	require.NoError(t, err)

	require.Equal(t, expectedURL, actualURL)
}

func TestURLUnmarshalYAML(t *testing.T) {
	t.Parallel()

	actualURL := types.URL{}
	require.NoError(t, yaml.NewDecoder(strings.NewReader(`"https://example.com"`)).Decode(&actualURL))

	expectedURL, err := types.NewURL("https://example.com")
	require.NoError(t, err)

	require.Equal(t, expectedURL, actualURL)
}
