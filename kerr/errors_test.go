package kerr

import (
	"errors"
	"testing"
)

func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		err     error
		code    string
		message string
	}{
		{ErrWrongPassword, "WRONG_PASSWORD", "wrong password"},
		{ErrVaultExists, "VAULT_EXISTS", "vault already initialized"},
		{ErrNoVault, "NO_VAULT", "vault not initialized; run 'yako vault init' first"},
		{ErrEntryNotFound, "ENTRY_NOT_FOUND", "entry not found"},
		{ErrCorrupted, "CORRUPTED", "vault file corrupted or not a yako file"},
		{ErrNoIdentity, "NO_IDENTITY", "no identity key found; run 'yako key generate' first"},
		{ErrEmptyPassword, "EMPTY_PASSWORD", "password cannot be empty"},
		{ErrPassMismatch, "PASS_MISMATCH", "passwords do not match"},
		{ErrInvalidKey, "INVALID_KEY", "invalid public key"},
		{ErrNoRecipient, "NO_RECIPIENT", "specify --recipient or --self"},
		{ErrBothFlags, "BOTH_FLAGS", "use --recipient or --self, not both"},
		{ErrInvalidWordCount, "INVALID_WORD_COUNT", "recovery phrase has the wrong number of words"},
		{ErrUnknownWord, "UNKNOWN_WORD", "recovery phrase contains an unknown word"},
		{ErrChecksumMismatch, "CHECKSUM_MISMATCH", "recovery phrase checksum does not match"},
	}

	for _, tt := range tests {
		if !errors.Is(tt.err, tt.err) {
			t.Errorf("%s: errors.Is failed on itself", tt.code)
		}
		if tt.err.Error() != tt.message {
			t.Errorf("%s: got %q, want %q", tt.code, tt.err.Error(), tt.message)
		}
		var ke *Error
		if !errors.As(tt.err, &ke) {
			t.Errorf("%s: not an *Error", tt.code)
		} else if ke.Code != tt.code {
			t.Errorf("%s: code = %q", tt.code, ke.Code)
		}
	}
}

func TestEntryNotFound(t *testing.T) {
	err := EntryNotFound("test-entry")
	if err.Error() != `entry "test-entry" not found` {
		t.Fatalf("got %q", err.Error())
	}
	var ke *Error
	if !errors.As(err, &ke) {
		t.Fatal("not an *Error")
	}
	if ke.Code != "ENTRY_NOT_FOUND" {
		t.Fatalf("code = %q", ke.Code)
	}
}

func TestWrap(t *testing.T) {
	inner := errors.New("inner error")
	wrapped := Wrap(inner, "outer message")
	if wrapped.Error() != "outer message" {
		t.Fatalf("got %q", wrapped.Error())
	}
	if !errors.Is(wrapped, inner) {
		t.Fatal("wrap should preserve Is")
	}
}
