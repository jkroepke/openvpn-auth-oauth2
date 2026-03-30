package config

import (
	"encoding"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

//nolint:gochecknoglobals
var (
	textMarshalerType   = reflect.TypeFor[encoding.TextMarshaler]()
	textUnmarshalerType = reflect.TypeFor[encoding.TextUnmarshaler]()
	durationType        = reflect.TypeFor[time.Duration]()
	stringSliceType     = reflect.TypeFor[[]string]()
	urlPointerType      = reflect.TypeFor[*url.URL]()
)

func RegisterCobraFlags(cmd *cobra.Command) {
	registerFlagSet(cmd.Flags(), reflect.ValueOf(Defaults), "")
}

func registerFlagSet(flagSet *pflag.FlagSet, defaults reflect.Value, prefix string) {
	defaultsType := defaults.Type()
	if defaultsType.Kind() != reflect.Struct {
		panic(fmt.Sprintf("registerFlagSet expects a struct, got %s", defaultsType))
	}

	for i := range defaultsType.NumField() {
		field := defaultsType.Field(i)
		if !field.IsExported() {
			continue
		}

		flagName, ok := fieldFlagName(field)
		if !ok {
			continue
		}

		if prefix != "" {
			flagName = prefix + "." + flagName
		}

		fieldValue := defaults.Field(i)

		switch {
		case isLeafFlagType(field.Type):
			registerLeafFlag(flagSet, flagName, field, fieldValue)
		case field.Type.Kind() != reflect.Struct:
			panic(fmt.Sprintf("unsupported config field type %s for %s", field.Type, flagName))
		default:
			registerFlagSet(flagSet, fieldValue, flagName)
		}
	}
}

func registerLeafFlag(flagSet *pflag.FlagSet, name string, field reflect.StructField, defaultValue reflect.Value) {
	if flagSet.Lookup(name) != nil {
		return
	}

	usage := field.Tag.Get("help")
	fieldType := field.Type

	switch {
	case fieldType == durationType:
		flagSet.Duration(name, time.Duration(defaultValue.Int()), usage)
	case fieldType == stringSliceType:
		flagSet.StringSlice(name, stringSliceValue(defaultValue, name), usage)
	case fieldType == urlPointerType:
		flagSet.String(name, urlPointerValue(defaultValue, name), usage)
	case isTextFlagType(fieldType):
		textUnmarshaler, textMarshaler := textFlagValue(fieldType, defaultValue, name)
		flagSet.TextVar(textUnmarshaler, name, textMarshaler, usage)
	default:
		registerScalarFlag(flagSet, name, defaultValue.Interface(), usage)
	}
}

func urlPointerValue(defaultValue reflect.Value, name string) string {
	if defaultValue.IsNil() {
		return ""
	}

	value, ok := defaultValue.Interface().(*url.URL)
	if !ok {
		panic(fmt.Sprintf("unsupported URL pointer flag type %s for %s", defaultValue.Type(), name))
	}

	return value.String()
}

func stringSliceValue(defaultValue reflect.Value, name string) []string {
	value, ok := defaultValue.Interface().([]string)
	if !ok {
		panic(fmt.Sprintf("unsupported string slice flag type %s for %s", defaultValue.Type(), name))
	}

	return value
}

func textFlagValue(fieldType reflect.Type, defaultValue reflect.Value, name string) (encoding.TextUnmarshaler, encoding.TextMarshaler) {
	textValue := reflect.New(fieldType)
	textValue.Elem().Set(defaultValue)

	textUnmarshaler, ok := textValue.Interface().(encoding.TextUnmarshaler)
	if !ok {
		panic(fmt.Sprintf("unsupported text flag type %s for %s", fieldType, name))
	}

	textMarshaler, ok := defaultValue.Interface().(encoding.TextMarshaler)
	if !ok {
		panic(fmt.Sprintf("unsupported text flag type %s for %s", fieldType, name))
	}

	return textUnmarshaler, textMarshaler
}

func registerScalarFlag(flagSet *pflag.FlagSet, name string, value any, usage string) {
	switch value := value.(type) {
	case string:
		flagSet.String(name, value, usage)
	case bool:
		flagSet.Bool(name, value, usage)
	case int, int8, int16, int32, int64:
		registerSignedScalarFlag(flagSet, name, value, usage)
	case uint, uint8, uint16, uint32, uint64:
		registerUnsignedScalarFlag(flagSet, name, value, usage)
	case float32, float64:
		registerFloatScalarFlag(flagSet, name, value, usage)
	default:
		panic(fmt.Sprintf("unsupported config flag type %T for %s", value, name))
	}
}

func registerSignedScalarFlag(flagSet *pflag.FlagSet, name string, value any, usage string) {
	switch value := value.(type) {
	case int:
		flagSet.Int(name, value, usage)
	case int8:
		flagSet.Int8(name, value, usage)
	case int16:
		flagSet.Int16(name, value, usage)
	case int32:
		flagSet.Int32(name, value, usage)
	case int64:
		flagSet.Int64(name, value, usage)
	default:
		panic(fmt.Sprintf("unsupported signed config flag type %T for %s", value, name))
	}
}

func registerUnsignedScalarFlag(flagSet *pflag.FlagSet, name string, value any, usage string) {
	switch value := value.(type) {
	case uint:
		flagSet.Uint(name, value, usage)
	case uint8:
		flagSet.Uint8(name, value, usage)
	case uint16:
		flagSet.Uint16(name, value, usage)
	case uint32:
		flagSet.Uint32(name, value, usage)
	case uint64:
		flagSet.Uint64(name, value, usage)
	default:
		panic(fmt.Sprintf("unsupported unsigned config flag type %T for %s", value, name))
	}
}

func registerFloatScalarFlag(flagSet *pflag.FlagSet, name string, value any, usage string) {
	switch value := value.(type) {
	case float32:
		flagSet.Float32(name, value, usage)
	case float64:
		flagSet.Float64(name, value, usage)
	default:
		panic(fmt.Sprintf("unsupported float config flag type %T for %s", value, name))
	}
}

func isLeafFlagType(fieldType reflect.Type) bool {
	switch kind := fieldType.Kind(); {
	case fieldType == durationType, fieldType == stringSliceType, fieldType == urlPointerType, isTextFlagType(fieldType):
		return true
	case kind == reflect.String, kind == reflect.Bool:
		return true
	case isSignedIntKind(kind), isUnsignedIntKind(kind), isFloatKind(kind):
		return true
	default:
		return false
	}
}

func isSignedIntKind(kind reflect.Kind) bool {
	//nolint:exhaustive
	switch kind {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return true
	default:
		return false
	}
}

func isUnsignedIntKind(kind reflect.Kind) bool {
	//nolint:exhaustive
	switch kind {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return true
	default:
		return false
	}
}

func isFloatKind(kind reflect.Kind) bool {
	//nolint:exhaustive
	switch kind {
	case reflect.Float32, reflect.Float64:
		return true
	default:
		return false
	}
}

func isTextFlagType(fieldType reflect.Type) bool {
	return reflect.PointerTo(fieldType).Implements(textUnmarshalerType) && fieldType.Implements(textMarshalerType)
}

func fieldFlagName(field reflect.StructField) (string, bool) {
	flagName := strings.TrimSpace(field.Tag.Get("mapstructure"))
	if flagName == "" {
		return strings.ToLower(field.Name), true
	}

	flagName, _, _ = strings.Cut(flagName, ",")
	if flagName == "-" || flagName == "" {
		return "", false
	}

	return flagName, true
}
