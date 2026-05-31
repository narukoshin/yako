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

// init registers the pass command and its subcommands (add, get, list, copy, rm, edit, generate) with flag definitions.
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

// passCmd is the root for all password subcommands — add, get, list, copy, rm, edit, generate.
var passCmd = &cobra.Command{
	Use:   "pass",
	Short: "Manage passwords in the vault",
}

// passGenFlag and passLenFlag control whether a password is auto-generated and its length.
var (
	passGenFlag bool
	passLenFlag int
)

// passAddCmd adds a new entry, optionally generating the password when --generate/-g is set.
var passAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Add a new password entry",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runPassAdd(cmd, args[0])
	},
}

// passGetCmd displays a single entry's details (password, username, url, notes, folder, last updated).
var passGetCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Show a password entry",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runPassGet(args[0])
	},
}

// passListCmd prints a table of every entry with its name, username, and last-updated date.
var passListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all password entries",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runPassList()
	},
}

// passCopyCmd copies the password to the clipboard and schedules automatic clearing after 15 seconds.
var passCopyCmd = &cobra.Command{
	Use:   "copy <name>",
	Short: "Copy a password to the clipboard",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runPassCopy(args[0])
	},
}

// passRmCmd deletes an entry from the vault by its name.
var passRmCmd = &cobra.Command{
	Use:   "rm <name>",
	Short: "Remove a password entry",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runPassRm(args[0])
	},
}

// passEditCmd opens an interactive prompt to modify an entry; supports --generate/-g for a new random password.
var passEditCmd = &cobra.Command{
	Use:   "edit <name>",
	Short: "Edit a password entry",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runPassEdit(cmd, args[0])
	},
}

// passGenerateCmd prints a random password of the requested length (default 24) to stdout.
var passGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a random password",
	RunE: func(cmd *cobra.Command, args []string) error {
		length, _ := cmd.Flags().GetInt("length")
		return runPassGenerate(length)
	},
}

// unlockVault prompts for the master password, loads all entries, and returns both for subsequent operations.
// Callers must zero the returned byte slice when done.
func unlockVault() ([]byte, []vault.Entry, error) {
	pw, err := readPassphrase("Master password: ")
	if err != nil {
		return nil, nil, err
	}
	pwBytes := []byte(pw)
	entries, err := vault.Load(pwBytes)
	if err != nil {
		zeroBytes(pwBytes)
		return nil, nil, err
	}
	return pwBytes, entries, nil
}

// readLine prints a prompt and reads a full line from stdin (strips trailing newline).
func readLine(prompt string) (string, error) {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// readOptional prompts with a default value shown in brackets; an empty input keeps the current value.
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

// findEntry scans the entries slice for a matching name and returns its index and pointer, or -1/nil.
func findEntry(entries []vault.Entry, name string) (int, *vault.Entry) {
	for i, e := range entries {
		if e.Name == name {
			return i, &entries[i]
		}
	}
	return -1, nil
}

// runPassAdd prompts for entry fields (username, password, URL, notes, folder) and persists a new entry.
// If --generate is set the password is auto-created at the configured length.
func runPassAdd(cmd *cobra.Command, name string) error {
	if !vault.Exists() {
		return kerr.ErrNoVault
	}

	pw, entries, err := unlockVault()
	if err != nil {
		return err
	}
	defer zeroBytes(pw)

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
	folder, _ := readLine("Folder: ")

	entry := vault.NewEntry(name, username, password, url, notes, folder)
	entries = append(entries, entry)

	if err := vault.Save(pw, entries); err != nil {
		return err
	}

	fmt.Printf("Added entry %q\n", name)
	return nil
}

// runPassGet prints the full details of a single entry: password, username, URL, notes, folder, age.
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
	if entry.Folder != "" {
		fmt.Printf("Folder:   %s\n", entry.Folder)
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

// runPassList prints a table of all entries with their name, username, and update date.
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

// runPassRm removes the named entry from the vault and persists the change.
func runPassRm(name string) error {
	if !vault.Exists() {
		return kerr.ErrNoVault
	}

	pw, entries, err := unlockVault()
	if err != nil {
		return err
	}
	defer zeroBytes(pw)

	idx, _ := findEntry(entries, name)
	if idx == -1 {
		return kerr.EntryNotFound(name)
	}

	entries = append(entries[:idx], entries[idx+1:]...)

	if err := vault.Save(pw, entries); err != nil {
		return err
	}

	fmt.Printf("Removed entry %q\n", name)
	return nil
}

// runPassCopy copies the entry's password to the system clipboard and auto-clears it after 15 seconds.
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
	time.AfterFunc(15*time.Second, func() { clipboard.WriteAll("") })

	fmt.Printf("Password for %q copied to clipboard (will clear in 15s)\n", name)
	return nil
}

// runPassEdit interactively updates an entry's fields; blank password input leaves the existing one untouched.
func runPassEdit(cmd *cobra.Command, name string) error {
	if !vault.Exists() {
		return kerr.ErrNoVault
	}

	pw, entries, err := unlockVault()
	if err != nil {
		return err
	}
	defer zeroBytes(pw)

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
	folder, err := readOptional("Folder", entry.Folder)
	if err != nil {
		return err
	}

	entries[idx].Username = username
	entries[idx].Password = []byte(password)
	entries[idx].URL = url
	entries[idx].Notes = notes
	entries[idx].Folder = folder
	entries[idx].Updated = entry.Updated

	if err := vault.Save(pw, entries); err != nil {
		return err
	}

	fmt.Printf("Updated entry %q\n", name)
	return nil
}

// zeroBytes overwrites a byte slice with zeros to prevent sensitive data from lingering in memory.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// runPassGenerate prints a cryptographically random password of the requested length.
func runPassGenerate(length int) error {
	password, err := vault.GeneratePassword(length)
	if err != nil {
		return err
	}
	fmt.Println(password)
	return nil
}
