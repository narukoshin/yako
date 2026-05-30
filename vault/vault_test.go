package vault

import (
	"os"
	"testing"

	"github.com/narukoshin/yako/v1/config"
)

func TestInitAndLoad(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	if Exists() {
		t.Fatal("vault should not exist yet")
	}

	if err := Init([]byte("correct-horse-battery-staple")); err != nil {
		t.Fatalf("Init: %v", err)
	}

	if !Exists() {
		t.Fatal("vault should exist after init")
	}

	entries, err := Load([]byte("correct-horse-battery-staple"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(entries) != 0 {
		t.Fatalf("expected empty vault, got %d entries", len(entries))
	}
}

func TestLoadWrongPassword(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	if err := Init([]byte("correct-password")); err != nil {
		t.Fatalf("Init: %v", err)
	}

	_, err := Load([]byte("wrong-password"))
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestSaveAndLoadEntries(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	password := []byte("hunter2")
	if err := Init(password); err != nil {
		t.Fatalf("Init: %v", err)
	}

	entries := []Entry{
		NewEntry("example.com", "user@ex.com", "s3cret!", "https://example.com", "my account", ""),
		NewEntry("github.com", "enko", "gh-token-123", "https://github.com", "", ""),
	}

	if err := Save(password, entries); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(password)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(loaded) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(loaded))
	}

	if loaded[0].Name != "example.com" {
		t.Fatalf("entry 0 name: got %q, want %q", loaded[0].Name, "example.com")
	}
	if loaded[0].Username != "user@ex.com" {
		t.Fatalf("entry 0 username: got %q, want %q", loaded[0].Username, "user@ex.com")
	}
	if string(loaded[0].Password) != "s3cret!" {
		t.Fatalf("entry 0 password: got %q, want %q", string(loaded[0].Password), "s3cret!")
	}

	if loaded[1].Name != "github.com" {
		t.Fatalf("entry 1 name: got %q, want %q", loaded[1].Name, "github.com")
	}
}

func TestInitTwiceFails(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	if err := Init([]byte("pw")); err != nil {
		t.Fatalf("Init: %v", err)
	}

	if err := Init([]byte("pw2")); err == nil {
		t.Fatal("expected error for duplicate init")
	}
}

func TestCorruptedPayload(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	password := []byte("hunter2")
	if err := Init(password); err != nil {
		t.Fatalf("Init: %v", err)
	}

	data, err := os.ReadFile(config.VaultPath())
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	data[100] ^= 0xFF
	if err := os.WriteFile(config.VaultPath(), data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err = Load(password)
	if err == nil {
		t.Fatal("expected error for corrupted payload")
	}
}

func TestMultipleSavePreservesEntries(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	password := []byte("hunter2")
	if err := Init(password); err != nil {
		t.Fatalf("Init: %v", err)
	}

	entries := []Entry{
		NewEntry("site1", "u1", "p1", "", "", ""),
	}

	if err := Save(password, entries); err != nil {
		t.Fatalf("Save 1: %v", err)
	}

	entries2 := []Entry{
		NewEntry("site1", "u1", "p1", "", "", ""),
		NewEntry("site2", "u2", "p2", "", "", ""),
	}

	if err := Save(password, entries2); err != nil {
		t.Fatalf("Save 2: %v", err)
	}

	loaded, err := Load(password)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(loaded) != 2 {
		t.Fatalf("expected 2 entries after second save, got %d", len(loaded))
	}
}
