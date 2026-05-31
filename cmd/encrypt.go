package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/narukoshin/yako/v1/config"
	ck "github.com/narukoshin/yako/v1/crypto"
	"github.com/narukoshin/yako/v1/kerr"
)

// encryptRecipients holds -r/--recipient flag values for the encrypt command.
var encryptRecipients []string

// init registers the encrypt command and its flags.
func init() {
	rootCmd.AddCommand(encryptCmd)
	encryptCmd.Flags().StringArrayVarP(&encryptRecipients, "recipient", "r", nil, "Recipient: base64 pubkey or keyring name (can be specified multiple times)")
	encryptCmd.Flags().Bool("self", false, "Encrypt to your own public key")
	encryptCmd.Flags().StringP("output", "o", "", "Output file (default: stdout)")
}

// encryptCmd encrypts messages or files for one or more recipients using X25519 + XChaCha20-Poly1305.
var encryptCmd = &cobra.Command{
	Use:   "encrypt [file]",
	Short: "Encrypt a message or file for a recipient",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runEncrypt(cmd, args)
	},
}

// runEncrypt executes the encrypt command: resolves recipients, encrypts plaintext, and writes
//
//	output. Can encrypt to self (own pubkey) or to specified recipients from keyring/base64.
func runEncrypt(cmd *cobra.Command, args []string) error {
	self, _ := cmd.Flags().GetBool("self")
	output, _ := cmd.Flags().GetString("output")

	if len(encryptRecipients) == 0 && !self {
		return kerr.ErrNoRecipient
	}
	if len(encryptRecipients) > 0 && self {
		return kerr.ErrBothFlags
	}

	var plaintext []byte
	if len(args) > 0 {
		var err error
		plaintext, err = os.ReadFile(args[0])
		if err != nil {
			return fmt.Errorf("read file: %w", err)
		}
	} else {
		var err error
		plaintext, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("read stdin: %w", err)
		}
	}

	if self {
		pub, err := os.ReadFile(config.IdentityPubPath())
		if err != nil {
			return kerr.ErrNoIdentity
		}
		ciphertext, err := ck.EncryptAsymmetric(pub, plaintext)
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}
		if output != "" {
			if err := os.WriteFile(output, ciphertext, 0600); err != nil {
				return fmt.Errorf("write output: %w", err)
			}
			fmt.Fprintf(os.Stderr, "Encrypted to %s\n", output)
		} else {
			os.Stdout.Write(ciphertext)
		}
		return nil
	}

	recipientPubs := make([][]byte, 0, len(encryptRecipients))
	for _, r := range encryptRecipients {
		pub, err := resolveRecipient(r)
		if err != nil {
			return fmt.Errorf("recipient %q: %w", r, err)
		}
		recipientPubs = append(recipientPubs, pub)
	}

	ciphertext, err := ck.EncryptAsymmetricMulti(recipientPubs, plaintext)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	if output != "" {
		if err := os.WriteFile(output, ciphertext, 0600); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Encrypted to %s\n", output)
	} else {
		os.Stdout.Write(ciphertext)
	}

	return nil
}
