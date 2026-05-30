package cmd

import (
	"encoding/base64"
	"fmt"
	"os"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/narukoshin/yako/v1/config"
	ck "github.com/narukoshin/yako/v1/crypto"
	"github.com/narukoshin/yako/v1/kerr"
)

func init() {
	rootCmd.AddCommand(keyCmd)
	keyCmd.AddCommand(keyGenerateCmd)
	keyCmd.AddCommand(keyPubkeyCmd)
	keyCmd.AddCommand(keyFingerprintCmd)
}

var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Manage X25519 encryption keys",
}

var keyGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a new X25519 keypair",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runKeyGenerate()
	},
}

var keyPubkeyCmd = &cobra.Command{
	Use:   "pubkey",
	Short: "Print the public key (base64)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runKeyPubkey()
	},
}

var keyFingerprintCmd = &cobra.Command{
	Use:   "fingerprint",
	Short: "Print the public key fingerprint",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runKeyFingerprint()
	},
}

func readPassphrase(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	bytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read input: %w", err)
	}
	return string(bytes), nil
}

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

func runKeyPubkey() error {
	pub, err := os.ReadFile(config.IdentityPubPath())
	if err != nil {
		return kerr.ErrNoIdentity
	}
	fmt.Println(base64.StdEncoding.EncodeToString(pub))
	return nil
}

func runKeyFingerprint() error {
	pub, err := os.ReadFile(config.IdentityPubPath())
	if err != nil {
		return kerr.ErrNoIdentity
	}
	fmt.Println(ck.Fingerprint(pub))
	return nil
}

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
