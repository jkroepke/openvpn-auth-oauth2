package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

// docCmd represents the doc command.
var docCmd = &cobra.Command{
	Use:   "doc",
	Short: "Generate man pages",
	Long: `Generate man pages for the application.
This command will create a directory named "man" in the current working directory a
nd populate it with the generated man pages for all commands.`,
	RunE: func(_ *cobra.Command, args []string) error {
		header := &doc.GenManHeader{
			Title:   "MINE",
			Section: "3",
		}

		err := doc.GenManTree(rootCmd, header, args[0])
		if err != nil {
			return fmt.Errorf("error generating man pages: %w", err)
		}

		return nil
	},
	DisableFlagsInUseLine: true,
	Args:                  cobra.MatchAll(cobra.ExactArgs(1)),
}

func init() {
	rootCmd.AddCommand(docCmd)
}
