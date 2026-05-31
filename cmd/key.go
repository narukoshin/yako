package cmd

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/narukoshin/yako/v1/config"
	ck "github.com/narukoshin/yako/v1/crypto"
	"github.com/narukoshin/yako/v1/kerr"
)

// init registers the key command and all its subcommands (generate, pubkey, fingerprint, import, list, show, remove).
func init() {
	rootCmd.AddCommand(keyCmd)
	keyCmd.AddCommand(keyGenerateCmd)
	keyCmd.AddCommand(keyPubkeyCmd)
	keyCmd.AddCommand(keyFingerprintCmd)
	keyCmd.AddCommand(keyImportCmd)
	keyCmd.AddCommand(keyListCmd)
	keyCmd.AddCommand(keyShowCmd)
	keyCmd.AddCommand(keyRemoveCmd)
}

// keyCmd is the parent command for all key management subcommands.
var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Manage X25519 encryption keys",
}

// keyGenerateCmd generates a new X25519 keypair and saves identity + pubkey to disk.
var keyGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a new X25519 keypair",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runKeyGenerate()
	},
}

// keyPubkeyCmd prints the base64-encoded public key.
var keyPubkeyCmd = &cobra.Command{
	Use:   "pubkey",
	Short: "Print the public key (base64)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runKeyPubkey()
	},
}

// keyFingerprintCmd prints the public key fingerprint.
var keyFingerprintCmd = &cobra.Command{
	Use:   "fingerprint",
	Short: "Print the public key fingerprint",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runKeyFingerprint()
	},
}

// keyImportCmd imports a public key into the keyring by name.
var keyImportCmd = &cobra.Command{
	Use:   "import <name> [<file>]",
	Short: "Import a public key into the keyring",
	Long: `Import a public key and assign it a name for use with 'yako encrypt -r <name>'.
If no file is given, reads the public key from stdin.`,
	Args: cobra.RangeArgs(1, 2),
	RunE: func(_ *cobra.Command, args []string) error {
		return runKeyImport(args)
	},
}

// keyListCmd lists all keys in the keyring with their fingerprints.
var keyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all imported keys in the keyring",
	RunE: func(_ *cobra.Command, _ []string) error {
		return runKeyList()
	},
}

// keyShowCmd shows details of a specific key by name.
var keyShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Show details of an imported key",
	Args:  cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return runKeyShow(args[0])
	},
}

// keyRemoveCmd removes an imported key from the keyring by name.
var keyRemoveCmd = &cobra.Command{
	Use:     "remove <name>",
	Short:   "Remove an imported key from the keyring",
	Aliases: []string{"rm"},
	Args:    cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		return runKeyRemove(args[0])
	},
}

// readPassphrase reads a password from the terminal without echoing (uses term.ReadPassword).
func readPassphrase(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	bytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read input: %w", err)
	}
	return string(bytes), nil
}

// runKeyGenerate generates a new X25519 keypair, optionally encrypts the private key with a
//
//	passphrase, and saves identity + pubkey to disk. The private key is zeroed from memory after.
func runKeyGenerate() error {
	if err := config.EnsureDir(); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	priv, pub, err := ck.GenerateKeypair()
	if err != nil {
		return err
	}

	pass, err := readPassphrase("Enter passphrase (empty = no encryption): ")
	if err != nil {
		return err
	}

	if pass != "" {
		confirm, err := readPassphrase("Confirm passphrase: ")
		if err != nil {
			return err
		}
		if pass != confirm {
			return kerr.ErrPassMismatch
		}

		salt, err := ck.GenerateSalt()
		if err != nil {
			return err
		}

		key := ck.DeriveKey([]byte(pass), salt)
		encrypted, err := ck.Encrypt(key, priv)
		if err != nil {
			return err
		}

		blob := make([]byte, 0, len(salt)+len(encrypted))
		blob = append(blob, salt...)
		blob = append(blob, encrypted...)

		if err := os.WriteFile(config.IdentityPath(), blob, 0600); err != nil {
			return fmt.Errorf("write identity: %w", err)
		}
	} else {
		if err := os.WriteFile(config.IdentityPath(), priv, 0600); err != nil {
			return fmt.Errorf("write identity: %w", err)
		}
	}

	if err := os.WriteFile(config.IdentityPubPath(), pub, 0644); err != nil {
		return fmt.Errorf("write pubkey: %w", err)
	}

	for i := range priv {
		priv[i] = 0
	}

	fmt.Println("Public key:", base64.StdEncoding.EncodeToString(pub))
	fmt.Println("Fingerprint:", ck.Fingerprint(pub))
	return nil
}

// runKeyImport imports a public key from a file or stdin into the keyring with the given name.
func runKeyImport(args []string) error {
	name := args[0]

	var pubData []byte
	if len(args) > 1 {
		var err error
		pubData, err = os.ReadFile(args[1])
		if err != nil {
			return fmt.Errorf("read key file: %w", err)
		}
	} else {
		pubDataStr, err := readLine("Public key (base64): ")
		if err != nil {
			return err
		}
		pubData = []byte(pubDataStr)
	}

	pubData = []byte(pubData)
	pub, err := base64.StdEncoding.DecodeString(string(pubData))
	if err != nil {
		return kerr.ErrInvalidKey
	}
	if len(pub) != 32 {
		return kerr.ErrInvalidKey
	}

	if err := addToKeyring(name, pub); err != nil {
		return err
	}

	fmt.Printf("Imported key %q (fingerprint: %s)\n", name, ck.Fingerprint(pub))
	return nil
}

// runKeyList prints all keys in the keyring with their names and fingerprints.
func runKeyList() error {
	kr, err := loadKeyring()
	if err != nil {
		return err
	}

	if len(kr.Keys) == 0 {
		fmt.Println("No keys in keyring. Use 'yako key import' to add one.")
		return nil
	}

	fmt.Printf("%-20s %-20s\n", "Name", "Fingerprint")
	fmt.Println(strings.Repeat("─", 42))
	for _, k := range kr.Keys {
		fmt.Printf("%-20s %-20s\n", k.Name, k.Fingerprint)
	}
	return nil
}

// runKeyShow prints the details of a specific key by name.
func runKeyShow(name string) error {
	kr, err := loadKeyring()
	if err != nil {
		return err
	}

	for _, k := range kr.Keys {
		if k.Name == name {
			fmt.Printf("Name:        %s\n", k.Name)
			fmt.Printf("Fingerprint: %s\n", k.Fingerprint)
			fmt.Printf("Public key:  %s\n", k.PublicKey)
			return nil
		}
	}
	return kerr.ErrKeyNotFound(name)
}

// runKeyRemove removes a key from the keyring by name.
func runKeyRemove(name string) error {
	if err := removeFromKeyring(name); err != nil {
		return err
	}
	fmt.Printf("Removed key %q from keyring\n", name)
	return nil
}

// runKeyPubkey prints the base64-encoded public key from the identity file.
func runKeyPubkey() error {
	pub, err := os.ReadFile(config.IdentityPubPath())
	if err != nil {
		return kerr.ErrNoIdentity
	}
	fmt.Println(base64.StdEncoding.EncodeToString(pub))
	return nil
}

// runKeyFingerprint prints the fingerprint of the public identity key.
func runKeyFingerprint() error {
	pub, err := os.ReadFile(config.IdentityPubPath())
	if err != nil {
		return kerr.ErrNoIdentity
	}
	fmt.Println(ck.Fingerprint(pub))
	return nil
}

// loadPrivateKey reads the identity private key from disk, decrypting with a passphrase if
//
//	the key is encrypted (detected by size > raw key length). Zeroes the passphrase key after use.
func loadPrivateKey() ([]byte, error) {
	blob, err := os.ReadFile(config.IdentityPath())
	if err != nil {
		return nil, kerr.ErrNoIdentity
	}

	if len(blob) == ck.PrivateKeySize {
		return blob, nil
	}

	if len(blob) < ck.SaltLen+1 {
		return nil, kerr.ErrCorrupted
	}

	salt := blob[:ck.SaltLen]
	ciphertext := blob[ck.SaltLen:]

	pw, err := readPassphrase("Enter passphrase: ")
	if err != nil {
		return nil, err
	}

	key := ck.DeriveKey([]byte(pw), salt)
	priv, err := ck.Decrypt(key, ciphertext)
	for i := range key {
		key[i] = 0
	}
	if err != nil {
		return nil, kerr.ErrWrongPassword
	}

	return priv, nil
}
