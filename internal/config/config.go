package config

import (
	"encoding"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

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
// It supports the following types: string, bool, int, uint and [encoding.TextUnmarshaler].
// If the type is not supported, it panics.
//
//nolint:cyclop
func lookupEnvOrDefault[T any](key string, defaultValue T) T {
	envValue, ok := os.LookupEnv(getEnvironmentVariableByFlagName(key))
	if !ok {
		return defaultValue
	}

	switch typedValue := any(defaultValue).(type) {
	case string:
		return any(envValue).(T) //nolint:forcetypeassert
	case bool:
		if envValue == "true" {
			return any(true).(T) //nolint:forcetypeassert
		}

		return any(false).(T) //nolint:forcetypeassert
	case int:
		intValue, err := strconv.Atoi(envValue)
		if err != nil {
			return defaultValue
		}

		return any(intValue).(T) //nolint:forcetypeassert
	case uint:
		intValue, err := strconv.ParseUint(envValue, 10, 0)
		if err != nil {
			return defaultValue
		}

		return any(uint(intValue)).(T) //nolint:forcetypeassert
	case encoding.TextUnmarshaler:
		if err := typedValue.UnmarshalText([]byte(envValue)); err != nil {
			return defaultValue
		}

		return any(typedValue).(T) //nolint:forcetypeassert
	default:
		// If the type is not supported, panic
		panic(fmt.Sprintf("unsupported type %T for environment variable %s", defaultValue, key))
	}
}

// getEnvironmentVariableByFlagName converts a flag name to an environment variable name.
// It replaces all dots with underscores and all dashes with double underscores.
// It also converts the flag name to uppercase.
func getEnvironmentVariableByFlagName(flagName string) string {
	return "CONFIG_" + strings.ReplaceAll(strings.ReplaceAll(strings.ToUpper(flagName), ".", "_"), "-", "__")
}
