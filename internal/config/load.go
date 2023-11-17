package config

import (
	"fmt"
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/knadh/koanf/providers/structs"
	"github.com/knadh/koanf/v2"
	"github.com/mitchellh/mapstructure"
	flag "github.com/spf13/pflag"
)

const envPrefix = "CONFIG_"

func Load(mode int, configFile string, flagSet *flag.FlagSet) (Config, error) {
	var err error

	k := koanf.New(".")

	if err := k.Load(structs.Provider(Defaults, "koanf"), nil); err != nil {
		return Config{}, fmt.Errorf("loading defaults: %w", err)
	}

	if configFile != "" {
		if err := k.Load(file.Provider(configFile), yaml.Parser()); err != nil {
			return Config{}, fmt.Errorf("file provider: %w", err)
		}
	}

	if flagSet != nil {
		if err = k.Load(posflag.Provider(flagSet, ".", k), nil); err != nil {
			return Config{}, fmt.Errorf("posflag provider: %w", err)
		}
	}

	err = k.Load(env.ProviderWithValue(envPrefix, ".",
		func(envKey string, envValue string) (string, interface{}) {
			key := strings.ToLower(strings.TrimPrefix(envKey, envPrefix))
			key = strings.ReplaceAll(key, "__", "-")
			key = strings.ReplaceAll(key, "_", ".")

			// If there is a space in the value, split the value into a slice by the space.
			if strings.Contains(envValue, " ") {
				return key, strings.Split(envValue, " ")
			}

			// Otherwise, return the plain string.
			return key, envValue
		}), nil,
	)

	if err != nil {
		return Config{}, fmt.Errorf("env provider: %w", err)
	}

	var conf Config
	unmarshalConf := koanf.UnmarshalConf{
		DecoderConfig: &mapstructure.DecoderConfig{
			DecodeHook: mapstructure.ComposeDecodeHookFunc(
				mapstructure.StringToTimeDurationHookFunc(),
				mapstructure.TextUnmarshallerHookFunc(),
				StringToURLHookFunc(),
				StringToTemplateHookFunc(),
			),
			Metadata:         nil,
			Result:           &conf,
			WeaklyTypedInput: true,
		},
	}

	if err = k.UnmarshalWithConf("", &conf, unmarshalConf); err != nil {
		return Config{}, fmt.Errorf("error unmarschal config: %w", err)
	}

	if err = Validate(mode, conf); err != nil {
		return Config{}, fmt.Errorf("validation error: %w", err)
	}

	return conf, nil
}
