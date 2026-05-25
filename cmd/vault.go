package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/narukoshin/yako/v1/config"
	"github.com/narukoshin/yako/v1/kerr"
	"github.com/narukoshin/yako/v1/vault"
)

func init() {
	rootCmd.AddCommand(vaultCmd)
	vaultCmd.AddCommand(vaultInitCmd)
	vaultCmd.AddCommand(vaultDestroyCmd)
}

var vaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Manage the password vault",
}

var vaultInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new password vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runVaultInit()
	},
}

var vaultDestroyCmd = &cobra.Command{
	Use:   "destroy",
	Short: "Delete the local vault file permanently",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runVaultDestroy()
	},
}

func runVaultInit() error {
	if vault.Exists() {
		return kerr.ErrVaultExists
	}

	pw, err := readAndConfirmPassword("Enter master password: ", "Confirm master password: ")
	if err != nil {
		return err
	}

	code, err := vault.InitWithRecovery([]byte(pw))
	if err != nil {
		return err
	}

	fmt.Println("Vault initialized at", config.VaultPath())
	fmt.Println()
	fmt.Println("RECOVERY PHRASE (12 words):")
	fmt.Println(code)
	fmt.Println()
	fmt.Println("Write this down and keep it safe. It can recover your vault")
	fmt.Println("if you forget your master password or change machines.")
	fmt.Println()
	return nil
}

func runVaultDestroy() error {
	if !vault.Exists() {
		return kerr.ErrNoVault
	}

	fmt.Print("Are you sure? This cannot be undone. (y/n): ")
	resp, err := readLine("")
	if err != nil {
		return err
	}
	if resp != "y" {
		fmt.Println("Cancelled")
		return nil
	}

	if err := os.Remove(config.VaultPath()); err != nil {
		return fmt.Errorf("destroy vault: %w", err)
	}

	fmt.Println("Vault destroyed at", config.VaultPath())
	return nil
}
