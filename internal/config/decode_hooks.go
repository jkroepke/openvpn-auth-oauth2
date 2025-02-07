//nolint:goerr113, wrapcheck
package config

import (
	"errors"
	"fmt"
	"path"
	"reflect"
	"text/template"

	"github.com/go-viper/mapstructure/v2"
)

// StringToTemplateHookFunc parse a string to [template.Template].
func StringToTemplateHookFunc() mapstructure.DecodeHookFuncType {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{},
	) (interface{}, error) {
		if f.Kind() != reflect.String {
			return data, nil
		}

		if t != reflect.TypeOf(template.Template{}) {
			return data, nil
		}

		dataString, ok := data.(string)
		if !ok {
			return nil, errors.New("unable to cast to string")
		}

		if dataString == "" {
			return template.Template{}, nil
		}

		tmpl, err := template.New(path.Base(dataString)).ParseFiles(dataString)
		if err != nil {
			return template.Template{}, fmt.Errorf("error paring template files: %w", err)
		}

		return tmpl, err
	}
}
