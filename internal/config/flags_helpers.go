package config

import (
	"encoding"
	"flag"
	"time"
)

// Helper methods for registering different flag types.
// These methods reduce boilerplate in the flagSet* functions.

//goland:noinspection GoMixedReceiverTypes
func (c *Config) registerBoolFlag(flagSet *flag.FlagSet, ptr *bool, name, usage string) {
	flagSet.BoolVar(ptr, name, lookupEnvOrDefault(name, *ptr), usage)
}

//goland:noinspection GoMixedReceiverTypes
func (c *Config) registerStringFlag(flagSet *flag.FlagSet, ptr *string, name, usage string) {
	flagSet.StringVar(ptr, name, lookupEnvOrDefault(name, *ptr), usage)
}

//goland:noinspection GoMixedReceiverTypes
func (c *Config) registerDurationFlag(flagSet *flag.FlagSet, ptr *time.Duration, name, usage string) {
	flagSet.DurationVar(ptr, name, lookupEnvOrDefault(name, *ptr), usage)
}

//goland:noinspection GoMixedReceiverTypes
func (c *Config) registerUintFlag(flagSet *flag.FlagSet, ptr *uint, name, usage string) {
	flagSet.UintVar(ptr, name, lookupEnvOrDefault(name, *ptr), usage)
}

// textValue is a helper interface that matches encoding.TextUnmarshaler and encoding.TextMarshaler.
type textValue interface {
	encoding.TextMarshaler
	encoding.TextUnmarshaler
}

//goland:noinspection GoMixedReceiverTypes
func (c *Config) registerTextFlag(flagSet *flag.FlagSet, ptr textValue, name, usage string) {
	flagSet.TextVar(ptr, name, lookupEnvOrDefault(name, ptr), usage)
}
