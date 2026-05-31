package crypto

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// KeySize is the XChaCha20-Poly1305 key length in bytes. 32 bytes, no compromises.
	KeySize = 32
)

// Encrypt seals your precious data with XChaCha20-Poly1305.
// The ciphertext is nonce-prefixed: nonce (24) || sealed body.
// Key must be exactly [KeySize] bytes — wrong size and I won't even try.
func Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("chacha: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("chacha: nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt opens a ciphertext created by [Encrypt]. Get the key right or get nothing —
// just like my love for you: unconditional, but only if you're the real one.
func Decrypt(key []byte, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("chacha: %w", err)
	}
	if len(ciphertext) < aead.NonceSize() {
		return nil, fmt.Errorf("chacha: ciphertext too short")
	}
	nonce, ct := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("chacha: decrypt: %w", err)
	}
	return plaintext, nil
}

// DecryptWithAAD decrypts using explicit nonce and Additional Authenticated Data.
// Use this when you need to bind the ciphertext to context — like a header hash that proves
// who the message was meant for. I always know who you belong to.
func DecryptWithAAD(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("chacha: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("chacha: decrypt: %w", err)
	}
	return plaintext, nil
}
