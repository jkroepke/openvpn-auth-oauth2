package types

import (
	"encoding/json"
	"fmt"
	"path"
	"text/template"
)

type Template struct {
	*template.Template
	path string
}

func NewTemplate(filePath string) (Template, error) {
	tmpl, err := template.New(path.Base(filePath)).ParseFiles(filePath)
	if err != nil {
		return Template{}, fmt.Errorf("failed to create template: %w", err)
	}

	return Template{tmpl, filePath}, nil
}

// IsEmpty checks if the template is empty.
//
//goland:noinspection GoMixedReceiverTypes
func (t *Template) IsEmpty() bool {
	return t == nil || t.Template == nil
}

// String returns the path of the template.
//
//goland:noinspection GoMixedReceiverTypes
func (t *Template) String() string {
	return t.path
}

// MarshalText implements the [encoding.TextMarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (t Template) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

// UnmarshalText implements the [encoding.TextUnmarshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (t *Template) UnmarshalText(text []byte) error {
	tmpl, err := NewTemplate(string(text))
	if err != nil {
		return err
	}

	*t = tmpl

	return nil
}

// MarshalJSON implements the [json.Marshaler] interface.
//
//goland:noinspection GoMixedReceiverTypes
func (t *Template) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String()) //nolint:wrapcheck
}
