package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	configArgument            = "--config"
	environmentVariablePrefix = "OPENVPN_AUTH_OAUTH2_"
)

var ErrVersion = errors.New("flag: version requested")

// New loads the configuration from defaults, a configuration file, environment variables, and command-line arguments.
//
//goland:noinspection GoMixedReceiverTypes
func New(args []string, writer io.Writer) (*Config, error) {
	config := Defaults

	if configFilePath := lookupConfigArgument(args); configFilePath != "" {
		if err := config.ReadFromConfigFile(configFilePath); err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
	}

	if err := config.ReadFromFlagAndEnvironment(args, writer); err != nil {
		return nil, err
	}

	return &config, nil
}

// ReadFromConfigFile reads the configuration from a configuration file.
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

	c.flagSetDebug(flagSet)
	c.flagSetLog(flagSet)
	c.flagSetHTTP(flagSet)
	c.flagSetOpenVPN(flagSet)
	c.flagSetOAuth2(flagSet)
	c.flagSetProvider(flagSet)

	flagSet.VisitAll(func(flag *flag.Flag) {
		if flag.Name == "version" {
			return
		}

		flag.Usage += fmt.Sprintf(" (env: %s)", getEnvironmentVariableByFlagName(flag.Name))
	})

	if err := applyEnvironment(flagSet); err != nil {
		return fmt.Errorf("error parsing environment variables: %w", err)
	}

	if err := flagSet.Parse(args[1:]); err != nil {
		return fmt.Errorf("error parsing command line arguments: %w", err)
	}

	if flagSet.NArg() != 0 {
		return errors.New("error parsing command line arguments: positional arguments are not supported")
	}

	if flagSet.Lookup("version").Value.String() == "true" {
		return ErrVersion
	}

	return nil
}

func lookupConfigArgument(args []string) string {
	readConfigPath := false

	for _, arg := range args {
		if readConfigPath {
			return arg
		}

		if configFile, ok := strings.CutPrefix(arg, configArgument+"="); ok {
			return configFile
		}

		readConfigPath = arg == configArgument
	}

	if readConfigPath {
		return ""
	}

	return os.Getenv(getEnvironmentVariableByFlagName("config"))
}

func applyEnvironment(flagSet *flag.FlagSet) error {
	flagsByEnvironmentVariable, err := getFlagsByEnvironmentVariable(flagSet)
	if err != nil {
		return err
	}

	environmentValues, err := getEnvironmentValues(flagsByEnvironmentVariable)
	if err != nil {
		return err
	}

	environmentVariableNames := make([]string, 0, len(environmentValues))
	for name := range environmentValues {
		environmentVariableNames = append(environmentVariableNames, name)
	}

	slices.Sort(environmentVariableNames)

	for _, name := range environmentVariableNames {
		if err = setEnvironmentValue(
			flagsByEnvironmentVariable[name],
			name,
			environmentValues[name],
		); err != nil {
			return err
		}
	}

	return nil
}

func getFlagsByEnvironmentVariable(flagSet *flag.FlagSet) (map[string]*flag.Flag, error) {
	flagsByEnvironmentVariable := make(map[string]*flag.Flag)

	var mappingError error

	flagSet.VisitAll(func(configurationFlag *flag.Flag) {
		if configurationFlag.Name == "version" {
			return
		}

		environmentVariable := getEnvironmentVariableByFlagName(configurationFlag.Name)
		if existingFlag, ok := flagsByEnvironmentVariable[environmentVariable]; ok {
			mappingError = fmt.Errorf(
				"environment variable %s maps to both %s and %s",
				environmentVariable,
				existingFlag.Name,
				configurationFlag.Name,
			)

			return
		}

		flagsByEnvironmentVariable[environmentVariable] = configurationFlag
	})

	if mappingError != nil {
		return nil, mappingError
	}

	return flagsByEnvironmentVariable, nil
}

func getEnvironmentValues(
	flagsByEnvironmentVariable map[string]*flag.Flag,
) (map[string]string, error) {
	environmentValues := make(map[string]string)
	unknownEnvironmentVariables := make([]string, 0)

	for _, entry := range os.Environ() {
		name, value, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(name, environmentVariablePrefix) {
			continue
		}

		if _, ok := flagsByEnvironmentVariable[name]; !ok {
			unknownEnvironmentVariables = append(unknownEnvironmentVariables, name)

			continue
		}

		environmentValues[name] = value
	}

	if len(unknownEnvironmentVariables) != 0 {
		slices.Sort(unknownEnvironmentVariables)

		return nil, fmt.Errorf(
			"unknown environment variables: %s",
			strings.Join(unknownEnvironmentVariables, ", "),
		)
	}

	return environmentValues, nil
}

func setEnvironmentValue(configurationFlag *flag.Flag, name, value string) error {
	if getter, ok := configurationFlag.Value.(flag.Getter); ok {
		if _, isBoolean := getter.Get().(bool); isBoolean && value != "true" && value != "false" {
			return fmt.Errorf("invalid value for environment variable %s: use true or false", name)
		}
	}

	if err := configurationFlag.Value.Set(value); err != nil {
		return fmt.Errorf("invalid value for environment variable %s: %w", name, err)
	}

	return nil
}

// getEnvironmentVariableByFlagName converts a flag name to an environment variable name.
// It replaces all dots and dashes with underscores.
// It also converts the flag name to uppercase.
func getEnvironmentVariableByFlagName(flagName string) string {
	if flagName == "config" {
		return environmentVariablePrefix + "CONFIG_FILE"
	}

	return environmentVariablePrefix +
		strings.NewReplacer(".", "_", "-", "_").Replace(strings.ToUpper(flagName))
}
