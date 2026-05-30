package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	ck "github.com/narukoshin/yako/v1/crypto"
)

func init() {
	rootCmd.AddCommand(decryptCmd)
	decryptCmd.Flags().StringP("output", "o", "", "Output file (default: stdout)")
}

var decryptCmd = &cobra.Command{
	Use:   "decrypt [file]",
	Short: "Decrypt a message or file",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runDecrypt(cmd, args)
	},
}

func runDecrypt(cmd *cobra.Command, args []string) error {
	output, _ := cmd.Flags().GetString("output")

	priv, err := loadPrivateKey()
	if err != nil {
		return err
	}

	var ciphertext []byte
	if len(args) > 0 {
		var err error
		ciphertext, err = os.ReadFile(args[0])
		if err != nil {
			return fmt.Errorf("read file: %w", err)
		}
	} else {
		var err error
		ciphertext, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("read stdin: %w", err)
		}
	}

	plaintext, err := ck.DecryptAsymmetric(priv, ciphertext)
	for i := range priv {
		priv[i] = 0
	}
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	if output != "" {
		if err := os.WriteFile(output, plaintext, 0600); err != nil {
			return fmt.Errorf("write output: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Decrypted to %s\n", output)
	} else {
		os.Stdout.Write(plaintext)
	}

	return nil
}
