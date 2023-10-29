package config_test

import (
	"net/url"
	"reflect"
	"testing"
	"text/template"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStringToURLHookFunc(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		f, t   reflect.Value
		result interface{}
		err    bool
	}{
		{"valid", reflect.ValueOf("http://localhost"), reflect.ValueOf(url.URL{}), &url.URL{Scheme: "http", Host: "localhost"}, false},
		{"invalid", reflect.ValueOf("invalid"), reflect.ValueOf(url.URL{}), nil, true},
		{"different type", reflect.ValueOf("5"), reflect.ValueOf("5"), "5", false},
	}

	for _, tt := range cases {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := config.StringToURLHookFunc()
			actual, err := mapstructure.DecodeHookExec(f, tt.f, tt.t)

			if tt.err {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.result, actual)
			assert.True(t, reflect.DeepEqual(actual, tt.result))
		})
	}
}

func TestStringToTemplateHookFunc(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		f, t   reflect.Value
		result interface{}
		err    bool
	}{
		{"valid", reflect.ValueOf("./../../README.md"), reflect.ValueOf(template.Template{}), func() *template.Template {
			tmpl, err := template.New("README.md").ParseFiles("./../../README.md")
			require.NoError(t, err)

			return tmpl
		}(), false},
		{"invalid", reflect.ValueOf("invalid"), reflect.ValueOf(template.Template{}), nil, true},
		{"different type", reflect.ValueOf("5"), reflect.ValueOf("5"), "5", false},
	}

	for _, tt := range cases {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := config.StringToTemplateHookFunc()
			actual, err := mapstructure.DecodeHookExec(f, tt.f, tt.t)

			if tt.err {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.result, actual)
			assert.True(t, reflect.DeepEqual(actual, tt.result))
		})
	}
}
