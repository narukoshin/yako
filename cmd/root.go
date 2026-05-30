package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/narukoshin/yako/v1/config"
)

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

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("⋯ version: %s\n⋯ author: Naru K ✗ AIRI (Technical Design)\n⋯ github: https://github.com/narukoshin\n", config.VERSION)
	},
}
