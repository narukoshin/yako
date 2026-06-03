package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	ck "github.com/narukoshin/yako/v1/crypto"
	"github.com/narukoshin/yako/v1/kerr"
	"github.com/narukoshin/yako/v1/vault"
)

// init registers the admin (config) command group and its subcommands.
func init() {
	rootCmd.AddCommand(adminCmd)
	adminCmd.AddCommand(changePasswordCmd)
	adminCmd.AddCommand(exportVaultCmd)
	adminCmd.AddCommand(recoverVaultCmd)
	adminCmd.AddCommand(generateRecoveryCmd)
}

// adminCmd groups maintenance operations (change-password, export, recover, generate-recovery).
var adminCmd = &cobra.Command{
	Use:    "config",
	Short:  "Configuration and maintenance (hidden)",
	Hidden: true,
}

// changePasswordCmd lets the user replace the master password by re-encrypting the vault.
var changePasswordCmd = &cobra.Command{
	Use:   "change-password",
	Short: "Change the vault master password",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runChangePassword()
	},
}

// exportVaultCmd dumps all vault entries as indented JSON to stdout.
var exportVaultCmd = &cobra.Command{
	Use:   "export",
	Short: "Export all entries as JSON",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runExportVault()
	},
}

// runChangePassword prompts for the current password, loads entries, and re-saves with a new master password.
func runChangePassword() error {
	if !vault.Exists() {
		return kerr.ErrNoVault
	}

	current, err := readPassphrase("Current master password: ")
	if err != nil {
		return err
	}
	defer ck.ZeroBytes(current)

	entries, err := vault.Load(current)
	if err != nil {
		return err
	}

	newPW, err := readAndConfirmPassword("New master password: ", "Confirm new master password: ")
	if err != nil {
		return err
	}
	defer ck.ZeroBytes(newPW)

	if err := vault.Save(newPW, entries); err != nil {
		return fmt.Errorf("change password: %w", err)
	}

	fmt.Println("Master password updated")
	return nil
}

// recoverVaultCmd recovers the vault on a new machine using a recovery phrase.
var recoverVaultCmd = &cobra.Command{
	Use:   "recover-vault",
	Short: "Recover vault after machine change",
	Long:  "Decrypt vault using recovery data and re-encrypt for this machine",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runRecoverVault()
	},
}

// generateRecoveryCmd produces a fresh recovery phrase (invalidates the old one).
var generateRecoveryCmd = &cobra.Command{
	Use:   "generate-recovery",
	Short: "Generate a new recovery phrase",
	Long:  "Decrypt vault with master password and generate a fresh recovery phrase",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runGenerateRecovery()
	},
}

// runRecoverVault reads a recovery phrase and re-encrypts the vault for this machine with a new password.
func runRecoverVault() error {
	if !vault.Exists() {
		return kerr.ErrNoVault
	}

	phrase, err := readLine(fmt.Sprintf("Recovery phrase (%d words, space-separated): ", vault.PhraseWords))
	if err != nil {
		return err
	}

	entries, err := vault.LoadRecoveryWithCode(phrase)
	if err != nil {
		fmt.Println("Recovery failed:", err)
		return err
	}

	return recoverVaultSetNewPassword(entries)
}

// recoverVaultSetNewPassword prompts for and saves a new master password after recovery.
func recoverVaultSetNewPassword(entries []vault.Entry) error {
	pw, err := readAndConfirmPassword("New master password: ", "Confirm new master password: ")
	if err != nil {
		return err
	}
	defer ck.ZeroBytes(pw)
	if err := vault.Save(pw, entries); err != nil {
		return fmt.Errorf("re-encrypt vault: %w", err)
	}
	fmt.Println("Vault recovered for this machine")
	return nil
}

// runGenerateRecovery decrypts the vault and generates a fresh recovery phrase, invalidating the old one.
func runGenerateRecovery() error {
	if !vault.Exists() {
		return kerr.ErrNoVault
	}

	pw, err := readPassphrase("Master password: ")
	if err != nil {
		return err
	}
	defer ck.ZeroBytes(pw)

	code, err := vault.RegenerateRecovery(pw)
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Printf("NEW RECOVERY PHRASE (%d words):\n", vault.PhraseWords)
	fmt.Println(code)
	fmt.Println()
	fmt.Println("Write this down and keep it safe. The old phrase is no longer valid.")
	fmt.Println()
	return nil
}

// runExportVault prompts for the master password and prints all entries as JSON to stdout.
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
	defer ck.ZeroBytes(pwBytes)

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
