package types_test

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/stretchr/testify/require"
)

//nolint:exhaustruct
func TestURLIsEmpty(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.expect, tt.url.IsEmpty())
		})
	}
}

func TestURLUnmarshalText(t *testing.T) {
	t.Parallel()

	actualURL := types.URL{}
	require.NoError(t, actualURL.UnmarshalText([]byte("https://example.com")))

	expectedURL, err := types.NewURL("https://example.com")
	require.NoError(t, err)

	require.Equal(t, expectedURL, actualURL)
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
	require.NoError(t, yaml.NewDecoder(strings.NewReader(`"https://example.com"`), yaml.UseJSONUnmarshaler()).Decode(&actualURL))

	expectedURL, err := types.NewURL("https://example.com")
	require.NoError(t, err)

	require.Equal(t, expectedURL, actualURL)
}
