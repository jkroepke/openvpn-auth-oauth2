package config

import (
	"encoding"
	"flag"
	"reflect"
	"time"
)

// registerFlagsFromStruct uses reflection to automatically register flags based on struct tags.
// It looks for `flag` and `usage` tags on struct fields to configure the flags.
//
//goland:noinspection GoMixedReceiverTypes
func (c *Config) registerFlagsFromStruct(flagSet *flag.FlagSet) {
	registerStructFlags(flagSet, reflect.ValueOf(c).Elem(), "")
}

// registerStructFlags recursively registers flags for all fields in a struct.
func registerStructFlags(flagSet *flag.FlagSet, v reflect.Value, prefix string) {
	t := v.Type()

	for i := range t.NumField() {
		field := t.Field(i)
		fieldValue := v.Field(i)

		// Skip unexported fields
		if !field.IsExported() {
			continue
		}

		// Get the flag name from the tag, or skip if not present
		flagName := field.Tag.Get("flag")
		if flagName == "" {
			// If this is a struct, recurse into it with the yaml tag as prefix
			recurseIntoNestedStruct(flagSet, field, fieldValue, prefix)

			continue
		}

		// Build full flag name with prefix
		fullFlagName := flagName
		if prefix != "" {
			fullFlagName = prefix + "." + flagName
		}

		usage := field.Tag.Get("usage")

		registerFieldFlag(flagSet, fieldValue, fullFlagName, usage)
	}
}

// recurseIntoNestedStruct handles recursion into nested structs that don't have a flag tag.
func recurseIntoNestedStruct(flagSet *flag.FlagSet, field reflect.StructField, fieldValue reflect.Value, prefix string) {
	if field.Type.Kind() != reflect.Struct || isSpecialType(field.Type) {
		return
	}

	newPrefix := prefix

	if yamlTag := field.Tag.Get("yaml"); yamlTag != "" && yamlTag != "-" {
		if newPrefix != "" {
			newPrefix += "."
		}

		newPrefix += yamlTag
	}

	registerStructFlags(flagSet, fieldValue, newPrefix)
}

// isSpecialType returns true for types that should not be recursed into.
// These are types that implement TextUnmarshaler or are time.Duration.
func isSpecialType(t reflect.Type) bool {
	// Check if it's a time.Duration
	if t == reflect.TypeFor[time.Duration]() {
		return true
	}

	// Check if it implements encoding.TextUnmarshaler
	textUnmarshalerType := reflect.TypeFor[encoding.TextUnmarshaler]()

	return reflect.PointerTo(t).Implements(textUnmarshalerType)
}

// registerFieldFlag registers a single field as a flag based on its type.
func registerFieldFlag(flagSet *flag.FlagSet, fieldValue reflect.Value, name, usage string) {
	fieldPtr := fieldValue.Addr().Interface()

	// Try to register based on type
	switch typedPtr := fieldPtr.(type) {
	case *bool:
		flagSet.BoolVar(typedPtr, name, lookupEnvOrDefault(name, *typedPtr), usage)
	case *string:
		flagSet.StringVar(typedPtr, name, lookupEnvOrDefault(name, *typedPtr), usage)
	case *int:
		flagSet.IntVar(typedPtr, name, lookupEnvOrDefault(name, *typedPtr), usage)
	case *uint:
		flagSet.UintVar(typedPtr, name, lookupEnvOrDefault(name, *typedPtr), usage)
	case *float64:
		flagSet.Float64Var(typedPtr, name, lookupEnvOrDefault(name, *typedPtr), usage)
	case *time.Duration:
		flagSet.DurationVar(typedPtr, name, lookupEnvOrDefault(name, *typedPtr), usage)
	default:
		// Try TextUnmarshaler interface
		if textPtr, ok := fieldPtr.(interface {
			encoding.TextMarshaler
			encoding.TextUnmarshaler
		}); ok {
			flagSet.TextVar(textPtr, name, lookupEnvOrDefault(name, textPtr), usage)

			return
		}

		// Unknown type - skip with warning (or could panic in strict mode)
	}
}
