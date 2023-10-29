//nolint:goerr113, wrapcheck
package config

import (
	"fmt"
	"net/url"
	"path"
	"reflect"
	"text/template"

	"github.com/mitchellh/mapstructure"
)

// StringToURLHookFunc parse a string to [url.URL].
func StringToURLHookFunc() mapstructure.DecodeHookFuncType {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{},
	) (interface{}, error) {
		if f.Kind() != reflect.String {
			return data, nil
		}

		if t != reflect.TypeOf(url.URL{}) {
			return data, nil
		}

		dataString, ok := data.(string)
		if !ok {
			return nil, fmt.Errorf("unable to cast to string")
		}

		// Convert it by parsing
		uri, err := url.Parse(dataString)
		if err != nil {
			return nil, err
		}

		if uri.String() == "" {
			return uri, nil
		}

		if uri.Scheme == "" {
			return nil, fmt.Errorf("invalid URL %s: empty scheme", dataString)
		}

		if uri.Host == "" && uri.Path == "" {
			return nil, fmt.Errorf("invalid URL %s: empty hostname", dataString)
		}

		return uri, nil
	}
}

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
			return nil, fmt.Errorf("unable to cast to string")
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
