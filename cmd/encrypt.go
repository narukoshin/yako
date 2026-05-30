package cmd

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/narukoshin/yako/v1/config"
	ck "github.com/narukoshin/yako/v1/crypto"
	"github.com/narukoshin/yako/v1/kerr"
)

func init() {
	rootCmd.AddCommand(encryptCmd)
	encryptCmd.Flags().StringP("recipient", "r", "", "Recipient's public key (base64)")
	encryptCmd.Flags().Bool("self", false, "Encrypt to your own public key")
	encryptCmd.Flags().StringP("output", "o", "", "Output file (default: stdout)")
}

var encryptCmd = &cobra.Command{
	Use:   "encrypt [file]",
	Short: "Encrypt a message or file for a recipient",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runEncrypt(cmd, args)
	},
}

func runEncrypt(cmd *cobra.Command, args []string) error {
	recipientB64, _ := cmd.Flags().GetString("recipient")
	self, _ := cmd.Flags().GetBool("self")
	output, _ := cmd.Flags().GetString("output")

	if recipientB64 == "" && !self {
		return kerr.ErrNoRecipient
	}
	if recipientB64 != "" && self {
		return kerr.ErrBothFlags
	}

	var recipientPub []byte
	if self {
		pub, err := os.ReadFile(config.IdentityPubPath())
		if err != nil {
			return kerr.ErrNoIdentity
		}
		recipientPub = pub
	} else {
		var err error
		recipientPub, err = base64.StdEncoding.DecodeString(strings.TrimSpace(recipientB64))
		if err != nil {
			return kerr.ErrInvalidKey
		}
		if len(recipientPub) != 32 {
			return kerr.ErrInvalidKey
		}
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

	ciphertext, err := ck.EncryptAsymmetric(recipientPub, plaintext)
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
