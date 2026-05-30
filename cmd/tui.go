package cmd

import (
	"github.com/spf13/cobra"

	"github.com/narukoshin/yako/v1/tui"
)

func init() {
	rootCmd.AddCommand(tuiCmd)
}

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Launch the interactive terminal UI",
	RunE: func(cmd *cobra.Command, args []string) error {
		return tui.Start()
	},
}
