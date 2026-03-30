package config //nolint:testpackage

import (
	"reflect"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testFlagConfig struct {
	HTTP    testFlagHTTP  `yaml:"http"`
	Timeout time.Duration `help:"timeout help" yaml:"timeout"`
	Values  []string      `help:"values help"  yaml:"values"`
	Hidden  string        `yaml:"-"`
}

type testFlagHTTP struct {
	Listen  string `help:"listen help" yaml:"listen"`
	Enabled bool   `yaml:"enabled"`
}

type testScalarKindsConfig struct {
	Signed   int16   `yaml:"signed"`
	Unsigned uint32  `yaml:"unsigned"`
	Ratio32  float32 `yaml:"ratio32"`
	Ratio64  float64 `yaml:"ratio64"`
}

type testUnsupportedFlagConfig struct {
	Values []int `yaml:"values"`
}

func TestRegisterCobraFlags(t *testing.T) {
	t.Parallel()

	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("config", "", "config file")

	RegisterCobraFlags(cmd)

	flags := cmd.Flags()
	require.NotNil(t, flags.Lookup("http.listen"))
	require.NotNil(t, flags.Lookup("openvpn.common-name.mode"))
	require.NotNil(t, flags.Lookup("oauth2.scopes"))
	assert.Equal(t, "config file", flags.Lookup("config").Usage)
	assert.Equal(t, Defaults.HTTP.Listen, flags.Lookup("http.listen").Value.String())
	assert.Equal(t, Defaults.OpenVPN.CommonName.Mode.String(), flags.Lookup("openvpn.common-name.mode").Value.String())
	assert.Equal(t, "[]", flags.Lookup("oauth2.scopes").Value.String())

	require.NoError(t, flags.Parse([]string{
		"--http.listen=:9443",
		"--openvpn.common-name.mode=omit",
		"--oauth2.scopes=openid,profile",
	}))

	assert.Equal(t, ":9443", flags.Lookup("http.listen").Value.String())
	assert.Equal(t, CommonNameModeOmit.String(), flags.Lookup("openvpn.common-name.mode").Value.String())
	assert.Equal(t, "[openid,profile]", flags.Lookup("oauth2.scopes").Value.String())
}

func TestRegisterFlagSetUsesHelpTags(t *testing.T) {
	t.Parallel()

	flagSet := pflag.NewFlagSet("test", pflag.ContinueOnError)
	registerFlagSet(flagSet, reflect.ValueOf(testFlagConfig{
		HTTP: testFlagHTTP{
			Listen:  ":9000",
			Enabled: true,
		},
		Timeout: time.Minute,
		Values:  []string{"one", "two"},
	}), "")

	require.NotNil(t, flagSet.Lookup("http.listen"))
	require.NotNil(t, flagSet.Lookup("http.enabled"))
	require.NotNil(t, flagSet.Lookup("timeout"))
	require.NotNil(t, flagSet.Lookup("values"))
	assert.Nil(t, flagSet.Lookup("hidden"))
	assert.Equal(t, "listen help", flagSet.Lookup("http.listen").Usage)
	assert.Empty(t, flagSet.Lookup("http.enabled").Usage)
	assert.Equal(t, "timeout help", flagSet.Lookup("timeout").Usage)
	assert.Equal(t, "values help", flagSet.Lookup("values").Usage)
	assert.Equal(t, "[one,two]", flagSet.Lookup("values").Value.String())

	require.NoError(t, flagSet.Parse([]string{
		"--http.listen=:9444",
		"--timeout=5s",
		"--values=alpha,beta",
		"--values=gamma",
	}))

	assert.Equal(t, ":9444", flagSet.Lookup("http.listen").Value.String())
	assert.Equal(t, "5s", flagSet.Lookup("timeout").Value.String())
	assert.Equal(t, "[alpha,beta,gamma]", flagSet.Lookup("values").Value.String())
}

func TestRegisterFlagSetSupportsScalarKinds(t *testing.T) {
	t.Parallel()

	flagSet := pflag.NewFlagSet("test", pflag.ContinueOnError)
	registerFlagSet(flagSet, reflect.ValueOf(testScalarKindsConfig{
		Signed:   -12,
		Unsigned: 42,
		Ratio32:  1.5,
		Ratio64:  2.75,
	}), "")

	assert.Equal(t, "-12", flagSet.Lookup("signed").Value.String())
	assert.Equal(t, "42", flagSet.Lookup("unsigned").Value.String())
	assert.Equal(t, "1.5", flagSet.Lookup("ratio32").Value.String())
	assert.Equal(t, "2.75", flagSet.Lookup("ratio64").Value.String())

	require.NoError(t, flagSet.Parse([]string{
		"--signed=-8",
		"--unsigned=7",
		"--ratio32=3.25",
		"--ratio64=9.5",
	}))

	assert.Equal(t, "-8", flagSet.Lookup("signed").Value.String())
	assert.Equal(t, "7", flagSet.Lookup("unsigned").Value.String())
	assert.Equal(t, "3.25", flagSet.Lookup("ratio32").Value.String())
	assert.Equal(t, "9.5", flagSet.Lookup("ratio64").Value.String())
}

func TestRegisterFlagSetSkipsExistingFlags(t *testing.T) {
	t.Parallel()

	flagSet := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flagSet.String("http.listen", "pre-existing", "keep me")

	registerFlagSet(flagSet, reflect.ValueOf(testFlagConfig{
		HTTP: testFlagHTTP{Listen: ":9000"},
	}), "")

	flag := flagSet.Lookup("http.listen")
	require.NotNil(t, flag)
	assert.Equal(t, "pre-existing", flag.DefValue)
	assert.Equal(t, "keep me", flag.Usage)
}

func TestRegisterFlagSetPanicsForUnsupportedFieldTypes(t *testing.T) {
	t.Parallel()

	flagSet := pflag.NewFlagSet("test", pflag.ContinueOnError)

	assert.PanicsWithValue(t,
		"unsupported config field type []int for values",
		func() {
			registerFlagSet(flagSet, reflect.ValueOf(testUnsupportedFlagConfig{}), "")
		},
	)
}
