package config_test

import (
	"io/fs"
	"os"
	"reflect"
	"testing"
	"text/template"

	"github.com/go-viper/mapstructure/v2"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestStringToFSHookFuncFunc(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		f, t   reflect.Value
		result interface{}
		err    bool
	}{
		{"valid", reflect.ValueOf("./../../"), reflect.Zero(reflect.TypeOf((*fs.FS)(nil)).Elem()), os.DirFS("./../../"), false},
		{"invalid file", reflect.ValueOf("./../../README.md"), reflect.Zero(reflect.TypeOf((*fs.FS)(nil)).Elem()), nil, true},
		{"invalid", reflect.ValueOf("invalid"), reflect.Zero(reflect.TypeOf((*fs.FS)(nil)).Elem()), nil, true},
		{"different type", reflect.ValueOf("5"), reflect.ValueOf("5"), "5", false},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := config.StringToFSHookFunc()
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
