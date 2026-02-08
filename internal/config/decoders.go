package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"reflect"
	"regexp"
	"strings"
	"text/template"

	"github.com/alecthomas/kong"
)

// templateMapper creates a mapper for *template.Template from file paths.
func templateMapper() kong.MapperFunc {
	return func(ctx *kong.DecodeContext, target reflect.Value) error {
		var text string
		if err := ctx.Scan.PopValueInto("string", &text); err != nil {
			return fmt.Errorf("error reading template path: %w", err)
		}

		if text == "" {
			return nil
		}

		tmpl, err := template.New(path.Base(text)).ParseFiles(text)
		if err != nil {
			return fmt.Errorf("failed to parse template: %w", err)
		}

		target.Set(reflect.ValueOf(tmpl))

		return nil
	}
}

// fsInterfaceMapper creates a mapper for fs.FS interface from file paths.
func fsInterfaceMapper() kong.MapperFunc {
	return func(ctx *kong.DecodeContext, target reflect.Value) error {
		var text string
		if err := ctx.Scan.PopValueInto("string", &text); err != nil {
			return fmt.Errorf("error reading fs.FS path: %w", err)
		}

		if text == "" {
			return errors.New("fs.FS path cannot be empty")
		}

		// Validate that the path exists and is a directory
		dirInfo, err := fs.Stat(os.DirFS(text), ".")
		if err != nil {
			return fmt.Errorf("error accessing path %q: %w", text, err)
		}

		if !dirInfo.IsDir() {
			return fmt.Errorf("path %q is not a directory", text)
		}

		// Create DirFS and set it to the target
		dirFS := os.DirFS(text)
		target.Set(reflect.ValueOf(dirFS))

		return nil
	}
}

// regexpSliceMapper creates a mapper for []*regexp.Regexp slices from comma-separated values.
func regexpSliceMapper() kong.MapperFunc {
	return func(ctx *kong.DecodeContext, target reflect.Value) error {
		var text string
		if err := ctx.Scan.PopValueInto("string", &text); err != nil {
			return fmt.Errorf("error reading regexp patterns: %w", err)
		}

		if text == "" {
			target.Set(reflect.ValueOf(nil))

			return nil
		}

		// Split by comma and compile each pattern
		patterns := strings.Split(text, ",")
		result := make([]*regexp.Regexp, 0, len(patterns))

		for _, pattern := range patterns {
			pattern = strings.TrimSpace(pattern)
			if pattern == "" {
				continue
			}

			// Wrap pattern with anchors if not already present
			if !strings.HasPrefix(pattern, "^") {
				pattern = "^(?:" + pattern + ")$"
			}

			re, err := regexp.Compile(pattern)
			if err != nil {
				return fmt.Errorf("invalid regexp pattern %q: %w", pattern, err)
			}

			result = append(result, re)
		}

		target.Set(reflect.ValueOf(result))

		return nil
	}
}
