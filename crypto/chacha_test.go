package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("hello, this is a secret message")

	ct, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := Decrypt(key, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Fatalf("got %q, want %q", got, plaintext)
	}
}

func TestEncryptDecryptEmpty(t *testing.T) {
	key := make([]byte, KeySize)

	ct, err := Encrypt(key, []byte{})
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}

	got, err := Decrypt(key, ct)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}

	if len(got) != 0 {
		t.Fatalf("expected empty, got %d bytes", len(got))
	}
}

func TestDecryptWrongKey(t *testing.T) {
	key := make([]byte, KeySize)
	key[0] = 1

	ct, err := Encrypt(key, []byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	wrongKey := make([]byte, KeySize)
	wrongKey[0] = 2

	_, err = Decrypt(wrongKey, ct)
	if err == nil {
		t.Fatal("expected error decrypting with wrong key")
	}
}

func TestDecryptWrongSize(t *testing.T) {
	_, err := Decrypt(make([]byte, KeySize), []byte("short"))
	if err == nil {
		t.Fatal("expected error for short ciphertext")
	}
}

func TestEncryptProducesUniqueNonces(t *testing.T) {
	key := make([]byte, KeySize)
	plaintext := []byte("same message")

	ct1, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt 1: %v", err)
	}

	ct2, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt 2: %v", err)
	}

	if bytes.Equal(ct1, ct2) {
		t.Fatal("two encryptions produced identical output (nonce reuse)")
	}
}

func TestEncryptWrongKeySize(t *testing.T) {
	_, err := Encrypt(make([]byte, 16), []byte("data"))
	if err == nil {
		t.Fatal("expected error for wrong key size")
	}
}

func TestDecryptWrongKeySize(t *testing.T) {
	_, err := Decrypt(make([]byte, 16), []byte("data"))
	if err == nil {
		t.Fatal("expected error for wrong key size")
	}
}
