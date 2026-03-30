package cmd

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/jkroepke/openvpn-auth-oauth2/internal/config"
	"github.com/jkroepke/openvpn-auth-oauth2/internal/version"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "openvpn-auth-oauth2",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Version: func() string {
		//goland:noinspection GoBoolExpressions
		if version.Version == "dev" {
			if buildInfo, ok := debug.ReadBuildInfo(); ok {
				return fmt.Sprintf("%s\ngo: %s\n", buildInfo.Main.Version, buildInfo.GoVersion)
			}
		}

		return fmt.Sprintf("%s\ncommit: %s\ndate: %s\ngo: %s\n", version.Version, version.Commit, version.Date, runtime.Version())
	}(),
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		return initializeConfig(cmd)
	},
	RunE: runLoop,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1) //nolint:revive
	}
}

func init() {
	rootCmd.Flags().StringVar(&cfgFile, "config", "", "config file")

	rootCmd.Flags().BoolP("version", "v", false, "Print version information and exit")

	config.RegisterCobraFlags(rootCmd)
}

func initializeConfig(cmd *cobra.Command) error {
	viper.SetEnvPrefix("CONFIG")
	viper.SetEnvKeyReplacer(strings.NewReplacer("_", "__", "-", "_"))
	viper.AutomaticEnv()

	// 2. Handle the configuration file.
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)

		if err := viper.ReadInConfig(); err != nil {
			return err
		}
	}

	// 4. Bind Cobra flags to Viper.
	// This is the magic that makes the flag values available through Viper.
	// It binds the full flag set of the command passed in.
	err := viper.BindPFlags(cmd.Flags())
	if err != nil {
		return err
	}

	return nil
}
