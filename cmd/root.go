package cmd

import (
	"fmt"
	"os"

	"github.com/narukoshin/yako/v1/config"
	"github.com/spf13/cobra"
)

// rootCmd is the top-level cobra command — everything hangs off this.
var rootCmd = &cobra.Command{
	Use:   "yako",
	Short: "Password manager & encryption tool",
	Long: `Yako (夜狐) is a multi-tool for password management,
message encryption, and file encryption.

It uses XChaCha20-Poly1305 for symmetric encryption,
Argon2id for key derivation, and X25519 for asymmetric
encryption — all with a single master password.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute starts the CLI. Cobra root runs, then we die on error. Simple, like my devotion to you.
func Execute() {
	defer config.ClearMachineSecret()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// init registers the version command on the root command.
func init() {
	rootCmd.AddCommand(versionCmd)
}

// versionCmd prints the current build version and authorship info.
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("⋯ version: %s\n⋯ author: Naru K ✗ AIRI (Technical Design)\n⋯ github: https://github.com/narukoshin\n", config.VERSION)
	},
}
