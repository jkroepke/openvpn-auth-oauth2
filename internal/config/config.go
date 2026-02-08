package config

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"reflect"
	"regexp"
	"strings"
	"text/template"

	"github.com/alecthomas/kong"
	"go.yaml.in/yaml/v3"
)

var ErrVersion = errors.New("flag: version requested")

// New loads the configuration from configuration files, command line arguments and environment variables in that order.
//
//goland:noinspection GoMixedReceiverTypes
func New(args []string, writer io.Writer) (Config, error) {
	config := Defaults

	// Get config file path early
	configFilePath := lookupConfigArgument(args)

	// Build Kong options
	options := buildKongOptions(writer, configFilePath)

	app, err := kong.New(&config, options...)
	if err != nil {
		return Config{}, fmt.Errorf("error creating parser: %w", err)
	}

	// Parse command line arguments
	_, err = app.Parse(args[1:])
	if err != nil {
		return Config{}, fmt.Errorf("error parsing command line arguments: %w", err)
	}

	return config, nil
}

// buildKongOptions creates the Kong parser options.
func buildKongOptions(writer io.Writer, configFilePath string) []kong.Option {
	options := []kong.Option{
		kong.Name("openvpn-auth-oauth2"),
		kong.Description("Documentation available at https://github.com/jkroepke/openvpn-auth-oauth2/wiki"),
		kong.Writers(writer, writer),
		kong.UsageOnError(),
		kong.Exit(func(int) {}), // Don't exit, just return error
		kong.ConfigureHelp(kong.HelpOptions{
			NoAppSummary: false,
			Compact:      false,
			Tree:         true,
		}),
		kong.TypeMapper(reflect.TypeFor[*template.Template](), templateMapper()),
		kong.TypeMapper(reflect.TypeFor[fs.FS](), fsInterfaceMapper()),
		kong.TypeMapper(reflect.TypeFor[[]*regexp.Regexp](), regexpSliceMapper()),
	}

	// Add YAML config file support if specified
	if configFilePath != "" {
		options = append(options, kong.Configuration(yamlConfigLoader, configFilePath))
	}

	return options
}

// lookupConfigArgument looks for --config flag in arguments to load YAML file early.
func lookupConfigArgument(args []string) string {
	for i, arg := range args {
		if arg == "--config" || arg == "--config-file" {
			if i+1 < len(args) {
				return args[i+1]
			}
		}

		if len(arg) > 14 && arg[:14] == "--config-file=" {
			return arg[14:]
		}
	}

	return ""
}

// yamlConfigLoader is a Kong ConfigurationLoader that reads YAML files.
func yamlConfigLoader(r io.Reader) (kong.Resolver, error) {
	var config map[string]any

	decoder := yaml.NewDecoder(r)
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		// Empty files are OK - just return an empty resolver
		if !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("error decoding YAML config: %w", err)
		}

		config = make(map[string]any)
	}

	return kong.ResolverFunc(func(_ *kong.Context, _ *kong.Path, flag *kong.Flag) (any, error) {
		if flag == nil {
			return nil, nil //nolint:nilnil
		}

		// Look up value in config map using the flag name
		value, ok := lookupConfigValue(config, flag.Name)
		if !ok {
			return nil, nil //nolint:nilnil
		}

		return value, nil
	}), nil
}

// lookupConfigValue searches for a configuration value in the nested map structure.
func lookupConfigValue(config map[string]any, key string) (any, bool) {
	// Try direct lookup
	if val, ok := config[key]; ok {
		return val, true
	}

	// Try with underscores replaced with hyphens
	key = strings.ReplaceAll(key, "_", "-")
	if val, ok := config[key]; ok {
		return val, true
	}

	return nil, false
}
