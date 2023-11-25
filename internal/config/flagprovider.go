package config

import (
	"errors"
	"flag"

	"github.com/knadh/koanf/maps"
)

// KoanfIntf is an interface that represents a small subset of methods
// used by this package from Koanf{}. When using this package, a live
// instance of Koanf{} should be passed.
type KoanfIntf interface {
	Exists(string) bool
}

// flagProvider implements a pflag command line provider.
type flagProvider struct {
	delim   string
	flagset *flag.FlagSet
	ko      KoanfIntf
	cb      func(key string, value string) (string, interface{})
}

// newFlagProvider returns a commandline flags provider that returns
// a nested map[string]interface{} of environment variable where the
// nesting hierarchy of keys are defined by delim. For instance, the
// delim "." will convert the key `parent.child.key: 1`
// to `{parent: {child: {key: 1}}}`.
//
// It takes an optional (but recommended) Koanf instance to see if the
// the flags defined have been set from other providers, for instance,
// a config file. If they are not, then the default values of the flags
// are merged. If they do exist, the flag values are not merged but only
// the values that have been explicitly set in the command line are merged.
func newFlagProvider(f *flag.FlagSet, delim string, ko KoanfIntf) *flagProvider {
	return &flagProvider{
		flagset: f,
		delim:   delim,
		ko:      ko,
	}
}

// Read reads the flag variables and returns a nested conf map.
func (p *flagProvider) Read() (map[string]interface{}, error) {
	mp := make(map[string]interface{})
	p.flagset.Visit(func(f *flag.Flag) {
		if p.cb != nil {
			key, value := p.cb(f.Name, f.Value.String())
			// If the callback blanked the key, it should be omitted
			if key == "" {
				return
			}
			mp[key] = value
		} else {
			mp[f.Name] = f.Value.String()
		}
	})

	if p.ko != nil {
		p.flagset.VisitAll(func(f *flag.Flag) {
			key := f.Name
			var value interface{} = f.Value.String()

			if p.cb != nil {
				key, value = p.cb(f.Name, f.Value.String())
				// If the callback blanked the key, it should be omitted
				if key == "" {
					return
				}
			}

			if p.ko.Exists(key) {
				return
			}

			if _, exists := mp[key]; exists {
				return
			}

			mp[key] = value
		})
	}

	return maps.Unflatten(mp, p.delim), nil
}

// ReadBytes is not supported by the basicflag koanf.
func (p *flagProvider) ReadBytes() ([]byte, error) {
	return nil, errors.New("basicflag provider does not support this method")
}
