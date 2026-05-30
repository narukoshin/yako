package vault

import (
	"errors"
	"os"
	"testing"

	"github.com/narukoshin/yako/v1/config"
	"github.com/narukoshin/yako/v1/kerr"
)

func TestVaultLockoutWrongPassword(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	if err := Init([]byte("correct-password")); err != nil {
		t.Fatalf("Init: %v", err)
	}

	for i := 0; i < 3; i++ {
		_, err := Load([]byte("wrong"))
		if err == nil {
			t.Fatalf("attempt %d: expected error", i+1)
		}
		if !errors.Is(err, kerr.ErrWrongPassword) {
			t.Fatalf("attempt %d: got %v, want ErrWrongPassword", i+1, err)
		}
	}

	_, err := Load([]byte("wrong"))
	if err == nil {
		t.Fatal("4th attempt: expected error")
	}
	if !errors.Is(err, kerr.ErrWrongPassword) {
		t.Fatalf("4th attempt: got %v, want ErrWrongPassword", err)
	}

	_, err = Load([]byte("correct-password"))
	if err == nil {
		t.Fatal("5th attempt: should be locked")
	}
	var ke *kerr.Error
	if !errors.As(err, &ke) || ke.Code != "LOCKED" {
		t.Fatalf("5th attempt: got %v, want LOCKED error", err)
	}

	if err := ResetLockout(); err != nil {
		t.Fatalf("ResetLockout: %v", err)
	}

	entries, err := Load([]byte("correct-password"))
	if err != nil {
		t.Fatalf("after reset: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected empty vault")
	}
}

func TestVaultCorrectPasswordResetsLockout(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	if err := Init([]byte("pw")); err != nil {
		t.Fatalf("Init: %v", err)
	}

	Load([]byte("wrong"))
	Load([]byte("wrong"))
	Load([]byte("wrong"))
	Load([]byte("wrong"))

	_, err := Load([]byte("correct-password"))
	if err == nil {
		t.Fatal("should be locked despite correct password")
	}

	if err := ResetLockout(); err != nil {
		t.Fatalf("ResetLockout: %v", err)
	}

	_, err = Load([]byte("pw"))
	if err != nil {
		t.Fatalf("correct password after reset: %v", err)
	}
}

func TestVaultBinaryFormat(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	if err := Init([]byte("test-pw")); err != nil {
		t.Fatalf("Init: %v", err)
	}

	entries := []Entry{
		NewEntry("example.com", "user", "pass", "", "", ""),
	}
	if err := Save([]byte("test-pw"), entries); err != nil {
		t.Fatalf("Save: %v", err)
	}

	data, err := readVaultFile()
	if err != nil {
		t.Fatalf("readVaultFile: %v", err)
	}

	if len(data) < headerFixedLen+payloadLenSize {
		t.Fatal("vault file too short for binary format")
	}

	if string(data[:5]) == "{" || string(data[:5]) == "{\n" {
		t.Fatal("vault file should not start with JSON brace")
	}

	loaded, err := Load([]byte("test-pw"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded) != 1 || loaded[0].Name != "example.com" {
		t.Fatalf("unexpected load result: %+v", loaded)
	}
}

func TestTamperedLockoutFailsClosed(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	if err := Init([]byte("mypw")); err != nil {
		t.Fatalf("Init: %v", err)
	}

	data, err := readVaultFile()
	if err != nil {
		t.Fatalf("readVaultFile: %v", err)
	}

	data[32] = 5
	os.WriteFile(config.VaultPath(), data, 0600)

	_, err = Load([]byte("mypw"))
	if err == nil {
		t.Fatal("expected error for tampered lockout HMAC")
	}
	if !errors.Is(err, kerr.ErrCorrupted) {
		t.Fatalf("got %v, want ErrCorrupted", err)
	}
}

func TestCorruptedPayloadFails(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	if err := Init([]byte("hunter2")); err != nil {
		t.Fatalf("Init: %v", err)
	}

	data, err := readVaultFile()
	if err != nil {
		t.Fatalf("readVaultFile: %v", err)
	}

	data[100] ^= 0xFF
	os.WriteFile(config.VaultPath(), data, 0600)

	_, err = Load([]byte("hunter2"))
	if err == nil {
		t.Fatal("expected error for corrupted payload")
	}
}
