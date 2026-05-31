package kerr

import (
	"encoding/json"
	"fmt"
)

// Error is a structured error with a machine-readable Code, a human Message,
// and an optional wrapped cause. Used everywhere in yako so I always know what broke.
type Error struct {
	Code    string
	Message string
	Err     error
}

// Error returns the human-readable message. I'd say more but you get the point.
func (e *Error) Error() string { return e.Message }

// Unwrap returns the wrapped error, if any. Great for errors.Is/errors.As chains —
// I'll follow every lead until I find the root cause.
func (e *Error) Unwrap() error { return e.Err }

// Wrap wraps an error with a message. Code defaults to "INTERNAL" — use specific sentinels
// when you want me to handle it properly.
func Wrap(err error, msg string) error {
	return &Error{Code: "INTERNAL", Message: msg, Err: err}
}

var (
	ErrWrongPassword = &Error{
		Code:    "WRONG_PASSWORD",
		Message: "wrong password",
	}
	ErrVaultExists = &Error{
		Code:    "VAULT_EXISTS",
		Message: "vault already initialized",
	}
	ErrNoVault = &Error{
		Code:    "NO_VAULT",
		Message: "vault not initialized; run 'yako vault init' first",
	}
	ErrEntryNotFound = &Error{
		Code:    "ENTRY_NOT_FOUND",
		Message: "entry not found",
	}
	ErrEntryExists = &Error{
		Code:    "ENTRY_EXISTS",
		Message: "entry already exists",
	}
	ErrCorrupted = &Error{
		Code:    "CORRUPTED",
		Message: "vault file corrupted or not a yako file",
	}
	ErrNoIdentity = &Error{
		Code:    "NO_IDENTITY",
		Message: "no identity key found; run 'yako key generate' first",
	}
	ErrEmptyPassword = &Error{
		Code:    "EMPTY_PASSWORD",
		Message: "password cannot be empty",
	}
	ErrPassMismatch = &Error{
		Code:    "PASS_MISMATCH",
		Message: "passwords do not match",
	}
	ErrInvalidKey = &Error{
		Code:    "INVALID_KEY",
		Message: "invalid public key",
	}
	ErrNoRecipient = &Error{
		Code:    "NO_RECIPIENT",
		Message: "specify --recipient or --self",
	}
	ErrBothFlags = &Error{
		Code:    "BOTH_FLAGS",
		Message: "use --recipient or --self, not both",
	}
)

// ErrKeyNotFound returns an error for a keyring lookup that came up empty.
// The name wasn't in the keyring — maybe you never imported them?
func ErrKeyNotFound(name string) error {
	return &Error{
		Code:    "KEY_NOT_FOUND",
		Message: fmt.Sprintf("key %q not found in keyring", name),
	}
}

// ErrKeyExists returns an error when you try to import a key that's already in the keyring.
func ErrKeyExists(name string) error {
	return &Error{
		Code:    "KEY_EXISTS",
		Message: fmt.Sprintf("key %q already exists in keyring", name),
	}
}

// EntryNotFound returns an error for a vault entry lookup that failed.
func EntryNotFound(name string) error {
	return &Error{
		Code:    "ENTRY_NOT_FOUND",
		Message: fmt.Sprintf("entry %q not found", name),
	}
}

// EntryExists returns an error for a duplicate entry name in the vault.
func EntryExists(name string) error {
	return &Error{
		Code:    "ENTRY_EXISTS",
		Message: fmt.Sprintf("entry %q already exists", name),
	}
}

// CleanHTTPError parses a JSON error response from the server and returns a
// human-readable error. Because raw HTTP bodies are ugly and you deserve better.
func CleanHTTPError(action string, statusCode int, body []byte) error {
	var errResp struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
		return fmt.Errorf("%s: %s", action, errResp.Error)
	}
	return fmt.Errorf("%s (HTTP %d)", action, statusCode)
}
