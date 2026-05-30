package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/narukoshin/yako/v1/kerr"
	"github.com/narukoshin/yako/v1/vault"
)

func init() {
	rootCmd.AddCommand(adminCmd)
	adminCmd.AddCommand(changePasswordCmd)
	adminCmd.AddCommand(exportVaultCmd)
	adminCmd.AddCommand(recoverVaultCmd)
	adminCmd.AddCommand(generateRecoveryCmd)
}

var adminCmd = &cobra.Command{
	Use:    "config",
	Short:  "Configuration and maintenance (hidden)",
	Hidden: true,
}

var changePasswordCmd = &cobra.Command{
	Use:   "change-password",
	Short: "Change the vault master password",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runChangePassword()
	},
}

var exportVaultCmd = &cobra.Command{
	Use:   "export",
	Short: "Export all entries as JSON",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runExportVault()
	},
}

func runChangePassword() error {
	if !vault.Exists() {
		return kerr.ErrNoVault
	}

	current, err := readPassphrase("Current master password: ")
	if err != nil {
		return err
	}

	entries, err := vault.Load([]byte(current))
	if err != nil {
		return err
	}

	newPW, err := readAndConfirmPassword("New master password: ", "Confirm new master password: ")
	if err != nil {
		return err
	}

	if err := vault.Save([]byte(newPW), entries); err != nil {
		return fmt.Errorf("change password: %w", err)
	}

	fmt.Println("Master password updated")
	return nil
}

var recoverVaultCmd = &cobra.Command{
	Use:   "recover-vault",
	Short: "Recover vault after machine change",
	Long:  "Decrypt vault using recovery data and re-encrypt for this machine",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runRecoverVault()
	},
}

var generateRecoveryCmd = &cobra.Command{
	Use:   "generate-recovery",
	Short: "Generate a new recovery phrase",
	Long:  "Decrypt vault with master password and generate a fresh recovery phrase",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runGenerateRecovery()
	},
}

func runRecoverVault() error {
	if !vault.Exists() {
		return kerr.ErrNoVault
	}

	phrase, err := readLine("Recovery phrase (12 words, space-separated): ")
	if err != nil {
		return err
	}

	entries, err := vault.LoadRecoveryWithCode(phrase)
	if err != nil {
		fmt.Println("Recovery failed: invalid phrase or vault format")
		return err
	}

	return recoverVaultSetNewPassword(entries)
}

func recoverVaultSetNewPassword(entries []vault.Entry) error {
	pw, err := readAndConfirmPassword("New master password: ", "Confirm new master password: ")
	if err != nil {
		return err
	}
	if err := vault.Save([]byte(pw), entries); err != nil {
		return fmt.Errorf("re-encrypt vault: %w", err)
	}
	fmt.Println("Vault recovered for this machine")
	return nil
}

func runGenerateRecovery() error {
	if !vault.Exists() {
		return kerr.ErrNoVault
	}

	pw, err := readPassphrase("Master password: ")
	if err != nil {
		return err
	}

	code, err := vault.RegenerateRecovery([]byte(pw))
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("NEW RECOVERY PHRASE (12 words):")
	fmt.Println(code)
	fmt.Println()
	fmt.Println("Write this down and keep it safe. The old phrase is no longer valid.")
	fmt.Println()
	return nil
}

func runExportVault() error {
	if !vault.Exists() {
		return kerr.ErrNoVault
	}

	fmt.Fprint(os.Stderr, "Master password: ")
	pwBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}

	entries, err := vault.Load(pwBytes)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("export: %w", err)
	}

	fmt.Println(string(data))
	return nil
}
