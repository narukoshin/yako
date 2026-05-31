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

// readAndConfirmPassword prompts twice, validates strength, and checks that both entries match before returning.
// Uses [readPassphrase] for masked input under the hood.
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

// checkPasswordStrength enforces the minimum bar: 12+ characters, at least one uppercase, one digit, and one symbol.
// Also triggers a [checkHIBP] call (non-blocking warning) so the user knows if their password has been breached.
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

// hibpClient is the HTTP client used to query the Have I Been Pwned API — replaceable for testing.
var hibpClient interface {
	Get(string) (*http.Response, error)
} = &http.Client{Timeout: 5 * time.Second}

// stderrWriter directs breach warnings to stderr so they don't pollute stdout pipelines.
var stderrWriter io.Writer = os.Stderr

// checkHIBP queries the Have I Been Pwned k-anonymity API using the first 5 hex chars of the SHA-1 hash.
// Prints a warning to stderr if the password appears in known breaches — never sends the full hash.
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
