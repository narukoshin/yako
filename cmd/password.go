package cmd

import (
	"crypto/sha1"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/narukoshin/yako/v1/kerr"
)

func readAndConfirmPassword(prompt, confirmPrompt string) (string, error) {
	pw, err := readPassphrase(prompt)
	if err != nil {
		return "", err
	}
	if pw == "" {
		return "", kerr.ErrEmptyPassword
	}
	if err := checkPasswordStrength(pw); err != nil {
		return "", err
	}
	confirm, err := readPassphrase(confirmPrompt)
	if err != nil {
		return "", err
	}
	if pw != confirm {
		return "", kerr.ErrPassMismatch
	}
	return pw, nil
}

func checkPasswordStrength(pw string) error {
	if len(pw) < 12 {
		return fmt.Errorf("password must be at least 12 characters")
	}

	hasUpper, hasDigit, hasSymbol := false, false, false
	for _, c := range pw {
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= '0' && c <= '9':
			hasDigit = true
		case c <= ' ' || c >= 127:
			continue
		default:
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
				hasSymbol = true
			}
		}
	}

	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !hasDigit {
		return fmt.Errorf("password must contain at least one digit")
	}
	if !hasSymbol {
		return fmt.Errorf("password must contain at least one symbol")
	}

	checkHIBP(pw)

	return nil
}

var hibpClient interface {
	Get(string) (*http.Response, error)
} = &http.Client{Timeout: 5 * time.Second}

var stderrWriter io.Writer = os.Stderr

func checkHIBP(pw string) {
	hash := sha1.Sum([]byte(pw))
	hexHash := fmt.Sprintf("%X", hash)
	prefix := hexHash[:5]
	suffix := hexHash[5:]

	resp, err := hibpClient.Get("https://api.pwnedpasswords.com/range/" + prefix)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, suffix) {
			fmt.Fprintln(stderrWriter, "Warning: this password has appeared in known data breaches (haveibeenpwned.com)")
			return
		}
	}
}
