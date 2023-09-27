package config

import (
	"errors"
	"html/template"
	"net/url"
	"reflect"

	"github.com/mitchellh/mapstructure"
)

func StringToUrlHookFunc() mapstructure.DecodeHookFunc {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{}) (interface{}, error) {
		if f.Kind() != reflect.String {
			return data, nil
		}
		if t != reflect.TypeOf(url.URL{}) {
			return data, nil
		}

		// Convert it by parsing
		uri, err := url.Parse(data.(string))
		if err != nil {
			return nil, err
		}

		if uri.String() == "" {
			return uri, nil
		}

		if uri.Scheme == "" {
			return nil, errors.New("invalid URL. empty scheme")
		}

		if uri.Host == "" && uri.Path == "" {
			return nil, errors.New("invalid URL. empty hostname")
		}

		return uri, nil
	}
}
func StringToTemplateHookFunc() mapstructure.DecodeHookFunc {
	return func(
		f reflect.Type,
		t reflect.Type,
		data interface{}) (interface{}, error) {
		if f.Kind() != reflect.String {
			return data, nil
		}

		if t != reflect.TypeOf(template.Template{}) {
			return data, nil
		}

		if data.(string) == "" {
			return template.Template{}, nil
		}

		return template.New("callback").ParseFiles(data.(string))
	}
}
