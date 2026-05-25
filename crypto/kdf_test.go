package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveKeyLength(t *testing.T) {
	salt := []byte("0123456789abcdef")
	key := DeriveKey([]byte("hunter2"), salt)

	if len(key) != KeyLen {
		t.Fatalf("key length: got %d, want %d", len(key), KeyLen)
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	salt := []byte("0123456789abcdef")
	k1 := DeriveKey([]byte("hunter2"), salt)
	k2 := DeriveKey([]byte("hunter2"), salt)

	if !bytes.Equal(k1, k2) {
		t.Fatal("same password + salt should produce same key")
	}
}

func TestDeriveKeyDifferentPassword(t *testing.T) {
	salt := []byte("0123456789abcdef")
	k1 := DeriveKey([]byte("password1"), salt)
	k2 := DeriveKey([]byte("password2"), salt)

	if bytes.Equal(k1, k2) {
		t.Fatal("different passwords should produce different keys")
	}
}

func TestDeriveKeyDifferentSalt(t *testing.T) {
	salt1 := []byte("0123456789abcdef")
	salt2 := []byte("fedcba9876543210")
	k1 := DeriveKey([]byte("hunter2"), salt1)
	k2 := DeriveKey([]byte("hunter2"), salt2)

	if bytes.Equal(k1, k2) {
		t.Fatal("different salts should produce different keys")
	}
}

func TestGenerateSaltLength(t *testing.T) {
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}
	if len(salt) != SaltLen {
		t.Fatalf("salt length: got %d, want %d", len(salt), SaltLen)
	}
}

func TestGenerateSaltUnique(t *testing.T) {
	s1, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt 1: %v", err)
	}
	s2, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt 2: %v", err)
	}
	if bytes.Equal(s1, s2) {
		t.Fatal("two salts should be different")
	}
}
