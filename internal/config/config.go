package config

import (
	"encoding"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

var ErrVersion = errors.New("flag: version requested")

// New loads the configuration from configuration files, command line arguments and environment variables in that order.
//
//goland:noinspection GoMixedReceiverTypes
func New(args []string, writer io.Writer) (Config, error) {
	config := Defaults

	if configFilePath := lookupConfigArgument(args); configFilePath != "" {
		if err := config.ReadFromConfigFile(configFilePath); err != nil && !errors.Is(err, io.EOF) {
			return Config{}, err
		}
	}

	if err := config.ReadFromFlagAndEnvironment(args, writer); err != nil {
		return Config{}, err
	}

	return config, nil
}

// ReadFromConfigFile reads the configuration from a configuration file and command line arguments.
//
//goland:noinspection GoMixedReceiverTypes
func (c *Config) ReadFromConfigFile(configFilePath string) error {
	configFile, err := os.Open(configFilePath)
	if err != nil {
		return fmt.Errorf("error opening config file %s: %w", configFilePath, err)
	}

	defer func() {
		_ = configFile.Close()
	}()

	decoder := yaml.NewDecoder(configFile)
	decoder.KnownFields(true)

	// Load the config file
	if err = decoder.Decode(c); err != nil {
		return fmt.Errorf("error decoding config file %s: %w", configFilePath, err)
	}

	return nil
}

// ReadFromFlagAndEnvironment reads the configuration from command line arguments and environment variables.
//
//goland:noinspection GoMixedReceiverTypes
func (c *Config) ReadFromFlagAndEnvironment(args []string, writer io.Writer) error {
	// Load the c from command line arguments
	flagSet := flag.NewFlagSet("openvpn-auth-oauth2", flag.ContinueOnError)
	flagSet.SetOutput(writer)
	flagSet.Usage = func() {
		_, _ = fmt.Fprint(flagSet.Output(), "Documentation available at https://github.com/jkroepke/openvpn-auth-oauth2/wiki\r\n\r\n")
		_, _ = fmt.Fprint(flagSet.Output(), "Usage of openvpn-auth-oauth2:\r\n\r\n")
		// --help should display options with double dash
		flagSet.VisitAll(func(flag *flag.Flag) {
			flag.Name = "-" + flag.Name
		})
		flagSet.PrintDefaults()
	}

	flagSet.String(
		"config",
		"",
		"path to one .yaml config file",
	)

	flagSet.Bool(
		"version",
		false,
		"show version",
	)

	// Register all flags from struct tags using reflection
	c.registerFlagsFromStruct(flagSet)

	flagSet.VisitAll(func(flag *flag.Flag) {
		if flag.Name == "version" {
			return
		}

		flag.Usage += fmt.Sprintf(" (env: %s)", getEnvironmentVariableByFlagName(flag.Name))
	})

	if err := flagSet.Parse(args[1:]); err != nil {
		return fmt.Errorf("error parsing command line arguments: %w", err)
	}

	if flagSet.Lookup("version").Value.String() == "true" {
		return ErrVersion
	}

	return nil
}

// lookupConfigArgument looks for the --config argument in the command line arguments
// and returns its value.
func lookupConfigArgument(args []string) string {
	var (
		configFile string
		ok         bool
	)

	for i, arg := range args {
		if !strings.HasPrefix(arg, "--config") {
			continue
		}

		configFile, ok = strings.CutPrefix(arg, "--config=")
		if ok {
			break
		}

		// check if the argument is --config without value and look for the next argument
		if len(args) > i+1 {
			configFile = args[i+1]

			break
		}
	}

	return configFile
}

// lookupEnvOrDefault looks up the environment variable by the flag name and returns the value.
// If the environment variable is not set, it returns the default value.
// It supports types implementing [encoding.TextUnmarshaler], as well as primitive types
// (string, bool, int, uint, float64, time.Duration).
// If the type is not supported, it panics.
func lookupEnvOrDefault[T any](key string, defaultValue T) T {
	envValue, ok := os.LookupEnv(getEnvironmentVariableByFlagName(key))
	if !ok {
		return defaultValue
	}

	// Try TextUnmarshaler first - this handles most custom types
	if result, ok := tryTextUnmarshal(envValue, defaultValue); ok {
		return result
	}

	// Fall back to primitive type handling
	return parsePrimitiveType(envValue, defaultValue)
}

// tryTextUnmarshal attempts to unmarshal the environment value using TextUnmarshaler interface.
// Returns the unmarshalled value and true if successful, or zero value and false otherwise.
func tryTextUnmarshal[T any](envValue string, defaultValue T) (T, bool) {
	t := reflect.TypeOf(defaultValue)

	var valPtr reflect.Value

	if t.Kind() == reflect.Pointer {
		valPtr = reflect.New(t.Elem())
	} else {
		valPtr = reflect.New(t)
	}

	unmarshaler, ok := valPtr.Interface().(encoding.TextUnmarshaler)
	if !ok {
		var zero T

		return zero, false
	}

	if err := unmarshaler.UnmarshalText([]byte(envValue)); err != nil {
		return defaultValue, true // Return default on parse error, but signal we handled it
	}

	if t.Kind() == reflect.Pointer {
		result, ok := valPtr.Convert(t).Interface().(T)

		return result, ok
	}

	result, ok := valPtr.Elem().Interface().(T)

	return result, ok
}

// parsePrimitiveType handles parsing of built-in primitive types.
//
//nolint:cyclop
func parsePrimitiveType[T any](envValue string, defaultValue T) T {
	var (
		value T
		ok    bool
	)

	switch any(defaultValue).(type) {
	case string:
		value, ok = any(envValue).(T)
	case bool:
		boolVal, err := strconv.ParseBool(envValue)
		if err != nil {
			return defaultValue
		}

		value, ok = any(boolVal).(T)
	case int:
		intValue, err := strconv.Atoi(envValue)
		if err != nil {
			return defaultValue
		}

		value, ok = any(intValue).(T)
	case uint:
		intValue, err := strconv.ParseUint(envValue, 10, 0)
		if err != nil {
			return defaultValue
		}

		value, ok = any(uint(intValue)).(T)
	case float64:
		floatValue, err := strconv.ParseFloat(envValue, 64)
		if err != nil {
			return defaultValue
		}

		value, ok = any(floatValue).(T)
	case time.Duration:
		durationValue, err := time.ParseDuration(envValue)
		if err != nil {
			return defaultValue
		}

		value, ok = any(durationValue).(T)
	default:
		panic(fmt.Sprintf("unsupported type %T for environment variable lookup", defaultValue))
	}

	if !ok {
		panic(fmt.Sprintf("failed to convert environment variable to type %T", defaultValue))
	}

	return value
}

// getEnvironmentVariableByFlagName converts a flag name to an environment variable name.
// It replaces all dots with underscores and all dashes with double underscores.
// It also converts the flag name to uppercase.
func getEnvironmentVariableByFlagName(flagName string) string {
	return "CONFIG_" + strings.ReplaceAll(strings.ReplaceAll(strings.ToUpper(flagName), ".", "_"), "-", "__")
}
