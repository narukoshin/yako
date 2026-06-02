package cmd

import (
	"fmt"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"github.com/narukoshin/yako/v1/config"
	ck "github.com/narukoshin/yako/v1/crypto"
	"github.com/narukoshin/yako/v1/kerr"
	"github.com/narukoshin/yako/v1/vault"
)

// init registers the vault command and its subcommands (init, destroy).
func init() {
	rootCmd.AddCommand(vaultCmd)
	vaultCmd.AddCommand(vaultInitCmd)
	vaultCmd.AddCommand(vaultDestroyCmd)
}

// vaultCmd is the parent command for vault management subcommands.
var vaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Manage the password vault",
}

// vaultInitCmd initializes a new password vault with recovery phrase generation.
var vaultInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new password vault",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runVaultInit()
	},
}

// vaultDestroyCmd deletes the local vault file (with optional remote deletion).
var vaultDestroyCmd = &cobra.Command{
	Use:   "destroy",
	Short: "Delete the local vault file permanently",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runVaultDestroy()
	},
}

// runVaultInit creates a new vault with a master password and recovery phrase.
func runVaultInit() error {
	if vault.Exists() {
		return kerr.ErrVaultExists
	}

	pw, err := readAndConfirmPassword("Enter master password: ", "Confirm master password: ")
	if err != nil {
		return err
	}
	defer ck.ZeroBytes(pw)

	code, err := vault.InitWithRecovery(pw)
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

// runVaultDestroy destroys the local vault and optionally the remote vault and remote config.
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

	rcPath := remoteConfigPath()
	if _, err := os.Stat(rcPath); err == nil {
		fmt.Print("Delete remote vault too? (y/n): ")
		resp, err := readLine("")
		if err != nil {
			return err
		}
		if resp == "y" {
			rc, err := loadRemoteConfig()
			if err == nil {
				accountResp, reqErr := doRequestWithRefresh("DELETE", apiURL(rc.ServerURL, "/account"), nil, rc)
				if reqErr == nil {
					accountResp.Body.Close()
					if accountResp.StatusCode == http.StatusOK {
						fmt.Println("Server account deleted")
					}
				}
			}
		}
		if err := os.Remove(rcPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove remote config: %w", err)
		}
	}

	fmt.Println("Vault destroyed at", config.VaultPath())
	return nil
}
