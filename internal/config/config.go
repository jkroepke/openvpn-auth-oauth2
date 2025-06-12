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

	"github.com/goccy/go-yaml"
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

	// Load the config file
	if err = yaml.NewDecoder(configFile, yaml.DisallowUnknownField(), yaml.UseJSONUnmarshaler()).Decode(c); err != nil {
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

	c.flagSetDebug(flagSet)
	c.flagSetLog(flagSet)
	c.flagSetHTTP(flagSet)
	c.flagSetOpenVPN(flagSet)
	c.flagSetOAuth2(flagSet)

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

func lookupConfigArgument(args []string) string {
	configFile := ""

	for i, arg := range args {
		if !strings.HasPrefix(arg, "--config") {
			continue
		}

		if strings.HasPrefix(arg, "--config=") {
			configFile = strings.TrimPrefix(arg, "--config=")

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
// It supports the following types: string, bool, int, uint, time.Duration and types implementing [encoding.TextUnmarshaler].
// If the type is not supported, it panics.
//
//nolint:cyclop
func lookupEnvOrDefault[T any](key string, defaultValue T) T {
	envValue, ok := os.LookupEnv(getEnvironmentVariableByFlagName(key))
	if !ok {
		return defaultValue
	}

	ok = false

	var value T

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
		// Handle types implementing encoding.TextUnmarshaler via reflection
		t := reflect.TypeOf(defaultValue)

		var valPtr reflect.Value

		if t.Kind() == reflect.Pointer {
			valPtr = reflect.New(t.Elem())
		} else {
			valPtr = reflect.New(t)
		}

		if unmarshaler, okUnmarshal := valPtr.Interface().(encoding.TextUnmarshaler); okUnmarshal {
			if err := unmarshaler.UnmarshalText([]byte(envValue)); err != nil {
				return defaultValue
			}

			if t.Kind() == reflect.Pointer {
				value, ok = valPtr.Convert(t).Interface().(T)
			} else {
				value, ok = valPtr.Elem().Interface().(T)
			}
		}
	}

	if !ok {
		panic(fmt.Sprintf("failed to convert environment variable %s to type %T", key, defaultValue))
	}

	return value
}

// getEnvironmentVariableByFlagName converts a flag name to an environment variable name.
// It replaces all dots with underscores and all dashes with double underscores.
// It also converts the flag name to uppercase.
func getEnvironmentVariableByFlagName(flagName string) string {
	return "CONFIG_" + strings.ReplaceAll(strings.ReplaceAll(strings.ToUpper(flagName), ".", "_"), "-", "__")
}
