package cmd

import (
	"github.com/spf13/cobra"

	"github.com/narukoshin/yako/v1/tui"
)

// init registers the tui command on the root command.
func init() {
	rootCmd.AddCommand(tuiCmd)
}

// tuiCmd launches the full-screen Bubble Tea terminal UI for vault management.
var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Launch the interactive terminal UI",
	RunE: func(cmd *cobra.Command, args []string) error {
		return tui.Start()
	},
}
