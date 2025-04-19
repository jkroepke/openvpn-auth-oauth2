//nolint:goerr113, wrapcheck
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
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

		tmpl, err := template.New(path.Base(dataString)).ParseFiles(dataString)
		if err != nil {
			return nil, fmt.Errorf("error parsing template files: %w", err)
		}

		return tmpl, err
	}
}

// StringToFSHookFunc parse a string to [fs.FS] using os.DirFS.
func StringToFSHookFunc() mapstructure.DecodeHookFuncType {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{},
	) (interface{}, error) {
		if f.Kind() != reflect.String {
			return data, nil
		}

		if !t.Implements(reflect.TypeOf((*fs.FS)(nil)).Elem()) {
			return data, nil
		}

		dataString, ok := data.(string)
		if !ok {
			return nil, errors.New("unable to cast to string")
		}

		dirFS := os.DirFS(dataString)

		dir, err := dirFS.Open(".")
		if err != nil {
			return nil, fmt.Errorf("error open filesystem: %w", err)
		}

		dirState, err := dir.Stat()
		if err != nil {
			return nil, fmt.Errorf("error stat filesystem: %w", err)
		}

		if !dirState.IsDir() {
			return nil, fmt.Errorf("path %s is not a directory", dataString)
		}

		return dirFS, err
	}
}
