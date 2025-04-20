package types_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config/types"
	"github.com/stretchr/testify/require"
)

func TestTemplate(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		input string
		err   string
	}{
		{
			"empty",
			"",
			"failed to create template: open :",
		},
		{
			"valid",
			"../../../README.md",
			"",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := types.NewTemplate(tc.input)
			if tc.err == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.err)
			}
		})
	}
}

//nolint:exhaustruct
func TestTemplateIsEmpty(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		template *types.Template
		expect   bool
	}{
		{
			"nil",
			nil,
			true,
		},
		{
			"empty",
			&types.Template{},
			true,
		},
		{
			"non-empty",
			&config.Defaults.HTTP.Template,
			false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.expect, tc.template.IsEmpty())
		})
	}
}

func TestTemplateUnmarshalText(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		input string
		err   string
	}{
		{
			"empty",
			"",
			"failed to create template: open :",
		},
		{
			"valid",
			"../../../README.md",
			"",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			actualURL := types.Template{}
			err := actualURL.UnmarshalText([]byte(tc.input))
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)

				return
			}

			require.NoError(t, err)

			expectedURL, err := types.NewTemplate(tc.input)
			require.NoError(t, err)

			require.Equal(t, expectedURL, actualURL)
		})
	}
}

func TestTemplateMarshalText(t *testing.T) {
	t.Parallel()

	actualTmpl, err := types.NewTemplate("../../../README.md")
	require.NoError(t, err)

	tmplBytes, err := actualTmpl.MarshalText()
	require.NoError(t, err)

	require.Equal(t, []byte("../../../README.md"), tmplBytes)
}

func TestTemplateUnmarshalJSON(t *testing.T) {
	t.Parallel()

	actualTmpl := types.Template{}
	require.NoError(t, json.NewDecoder(strings.NewReader(`"../../../README.md"`)).Decode(&actualTmpl))

	expectedTmpl, err := types.NewTemplate("../../../README.md")
	require.NoError(t, err)

	require.Equal(t, expectedTmpl, actualTmpl)
}

func TestTemplateUnmarshalYAML(t *testing.T) {
	t.Parallel()

	actualTmpl := types.Template{}
	require.NoError(t, yaml.NewDecoder(strings.NewReader(`"../../../README.md"`), yaml.UseJSONUnmarshaler()).Decode(&actualTmpl))

	expectedTmpl, err := types.NewTemplate("../../../README.md")
	require.NoError(t, err)

	require.Equal(t, expectedTmpl, actualTmpl)
}
