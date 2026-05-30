package kerr

import (
	"encoding/json"
	"fmt"
)

type Error struct {
	Code    string
	Message string
	Err     error
}

func (e *Error) Error() string { return e.Message }

func (e *Error) Unwrap() error { return e.Err }

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

func EntryNotFound(name string) error {
	return &Error{
		Code:    "ENTRY_NOT_FOUND",
		Message: fmt.Sprintf("entry %q not found", name),
	}
}

func EntryExists(name string) error {
	return &Error{
		Code:    "ENTRY_EXISTS",
		Message: fmt.Sprintf("entry %q already exists", name),
	}
}

func CleanHTTPError(action string, statusCode int, body []byte) error {
	var errResp struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
		return fmt.Errorf("%s: %s", action, errResp.Error)
	}
	return fmt.Errorf("%s (HTTP %d)", action, statusCode)
}
