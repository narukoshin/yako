package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/atotto/clipboard"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/narukoshin/yako/v1/kerr"
	"github.com/narukoshin/yako/v1/vault"
)

func init() {
	rootCmd.AddCommand(passCmd)
	passCmd.AddCommand(passAddCmd)
	passCmd.AddCommand(passGetCmd)
	passCmd.AddCommand(passListCmd)
	passCmd.AddCommand(passRmCmd)
	passCmd.AddCommand(passEditCmd)
	passCmd.AddCommand(passCopyCmd)
	passCmd.AddCommand(passGenerateCmd)

	passAddCmd.Flags().BoolVarP(&passGenFlag, "generate", "g", false, "Generate a random password")
	passAddCmd.Flags().IntVarP(&passLenFlag, "length", "l", 24, "Generated password length")

	passEditCmd.Flags().BoolVarP(&passGenFlag, "generate", "g", false, "Generate a random password")
	passEditCmd.Flags().IntVarP(&passLenFlag, "length", "l", 24, "Generated password length")

	passGenerateCmd.Flags().IntP("length", "l", 24, "Password length")
}

var passCmd = &cobra.Command{
	Use:   "pass",
	Short: "Manage passwords in the vault",
}

var (
	passGenFlag bool
	passLenFlag int
)

var passAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Add a new password entry",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runPassAdd(cmd, args[0])
	},
}

var passGetCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Show a password entry",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runPassGet(args[0])
	},
}

var passListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all password entries",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runPassList()
	},
}

var passCopyCmd = &cobra.Command{
	Use:   "copy <name>",
	Short: "Copy a password to the clipboard",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runPassCopy(args[0])
	},
}

var passRmCmd = &cobra.Command{
	Use:   "rm <name>",
	Short: "Remove a password entry",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runPassRm(args[0])
	},
}

var passEditCmd = &cobra.Command{
	Use:   "edit <name>",
	Short: "Edit a password entry",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runPassEdit(cmd, args[0])
	},
}

var passGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a random password",
	RunE: func(cmd *cobra.Command, args []string) error {
		length, _ := cmd.Flags().GetInt("length")
		return runPassGenerate(length)
	},
}

func unlockVault() (string, []vault.Entry, error) {
	pw, err := readPassphrase("Master password: ")
	if err != nil {
		return "", nil, err
	}
	entries, err := vault.Load([]byte(pw))
	if err != nil {
		return "", nil, err
	}
	return pw, entries, nil
}

func readLine(prompt string) (string, error) {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func readOptional(prompt, current string) (string, error) {
	fmt.Printf("%s [%s]: ", prompt, current)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return current, nil
	}
	return line, nil
}

func findEntry(entries []vault.Entry, name string) (int, *vault.Entry) {
	for i, e := range entries {
		if e.Name == name {
			return i, &entries[i]
		}
	}
	return -1, nil
}

func runPassAdd(cmd *cobra.Command, name string) error {
	if !vault.Exists() {
		return kerr.ErrNoVault
	}

	pw, entries, err := unlockVault()
	if err != nil {
		return err
	}

	if _, existing := findEntry(entries, name); existing != nil {
		return kerr.EntryExists(name)
	}

	username, _ := readLine("Username: ")
	var password string
	if passGenFlag {
		password, err = vault.GeneratePassword(passLenFlag)
		if err != nil {
			return err
		}
		fmt.Printf("Generated password (%d chars)\n", passLenFlag)
	} else {
		password, err = readPassphrase("Password: ")
		if err != nil {
			return err
		}
		if password == "" {
			return kerr.ErrEmptyPassword
		}
	}
	url, _ := readLine("URL: ")
	notes, _ := readLine("Notes: ")

	entry := vault.NewEntry(name, username, password, url, notes)
	entries = append(entries, entry)

	if err := vault.Save([]byte(pw), entries); err != nil {
		return err
	}

	fmt.Printf("Added entry %q\n", name)
	return nil
}

func runPassGet(name string) error {
	if !vault.Exists() {
		return kerr.ErrNoVault
	}

	_, entries, err := unlockVault()
	if err != nil {
		return err
	}

	_, entry := findEntry(entries, name)
	if entry == nil {
		return kerr.EntryNotFound(name)
	}

	fmt.Printf("Name:     %s\n", entry.Name)
	fmt.Printf("Password: %s\n", string(entry.Password))
	if entry.Username != "" {
		fmt.Printf("Username: %s\n", entry.Username)
	}
	if entry.URL != "" {
		fmt.Printf("URL:      %s\n", entry.URL)
	}
	if entry.Notes != "" {
		fmt.Printf("Notes:    %s\n", entry.Notes)
	}
	if entry.Updated != "" {
		if t, err := time.Parse(time.RFC3339, entry.Updated); err == nil {
			fmt.Printf("Updated:  %s\n", kerr.TimeAgo(t))
		}
	}
	return nil
}

func runPassList() error {
	if !vault.Exists() {
		return kerr.ErrNoVault
	}

	_, entries, err := unlockVault()
	if err != nil {
		return err
	}

	if len(entries) == 0 {
		fmt.Println("No entries in vault")
		return nil
	}

	fmt.Printf("%-24s %-24s %s\n", "Name", "Username", "Updated")
	fmt.Println(strings.Repeat("-", 72))
	for _, e := range entries {
		updated := e.Updated
		if len(updated) > 19 {
			updated = updated[:10]
		}
		fmt.Printf("%-24s %-24s %s\n", e.Name, e.Username, updated)
	}
	return nil
}

func runPassRm(name string) error {
	if !vault.Exists() {
		return kerr.ErrNoVault
	}

	pw, entries, err := unlockVault()
	if err != nil {
		return err
	}

	idx, _ := findEntry(entries, name)
	if idx == -1 {
		return kerr.EntryNotFound(name)
	}

	entries = append(entries[:idx], entries[idx+1:]...)

	if err := vault.Save([]byte(pw), entries); err != nil {
		return err
	}

	fmt.Printf("Removed entry %q\n", name)
	return nil
}

func runPassCopy(name string) error {
	if !vault.Exists() {
		return kerr.ErrNoVault
	}

	_, entries, err := unlockVault()
	if err != nil {
		return err
	}

	_, entry := findEntry(entries, name)
	if entry == nil {
		return kerr.EntryNotFound(name)
	}

	if err := clipboard.WriteAll(string(entry.Password)); err != nil {
		return fmt.Errorf("clipboard: %w", err)
	}
	time.AfterFunc(45*time.Second, func() { clipboard.WriteAll("") })

	fmt.Printf("Password for %q copied to clipboard (will clear in 45s)\n", name)
	return nil
}

func runPassEdit(cmd *cobra.Command, name string) error {
	if !vault.Exists() {
		return kerr.ErrNoVault
	}

	pw, entries, err := unlockVault()
	if err != nil {
		return err
	}

	idx, entry := findEntry(entries, name)
	if entry == nil {
		return kerr.EntryNotFound(name)
	}

	username, err := readOptional("Username", entry.Username)
	if err != nil {
		return err
	}
	var password string
	if passGenFlag {
		password, err = vault.GeneratePassword(passLenFlag)
		if err != nil {
			return err
		}
		fmt.Printf("Generated password (%d chars)\n", passLenFlag)
	} else {
		fmt.Printf("Password [unchanged]: ")
		pwBytes, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			return err
		}
		password = string(pwBytes)
		if password == "" {
			password = string(entry.Password)
		}
	}
	url, err := readOptional("URL", entry.URL)
	if err != nil {
		return err
	}
	notes, err := readOptional("Notes", entry.Notes)
	if err != nil {
		return err
	}

	entries[idx].Username = username
	entries[idx].Password = []byte(password)
	entries[idx].URL = url
	entries[idx].Notes = notes
	entries[idx].Updated = entry.Updated

	if err := vault.Save([]byte(pw), entries); err != nil {
		return err
	}

	fmt.Printf("Updated entry %q\n", name)
	return nil
}

func runPassGenerate(length int) error {
	password, err := vault.GeneratePassword(length)
	if err != nil {
		return err
	}
	fmt.Println(password)
	return nil
}
