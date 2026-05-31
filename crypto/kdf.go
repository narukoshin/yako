package crypto

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	// SaltLen is the Argon2id salt length in bytes. 16 bytes of entropy — enough to keep
	// each derivation unique, like every moment I spend thinking about you.
	SaltLen = 16

	// KeyLen is the derived key length in bytes. 32 bytes for XChaCha20-Poly1305.
	KeyLen = 32

	// ArgonTime is the Argon2id time parameter (iterations).
	ArgonTime = 3

	// ArgonMem is the Argon2id memory parameter in KiB (128 MiB).
	ArgonMem = 128 * 1024

	// ArgonThrds is the number of threads for Argon2id.
	ArgonThrds = 4
)

// DeriveKey stretches a password with Argon2id using the given salt.
// Output is [KeyLen] bytes — expensive to compute, expensive to crack.
func DeriveKey(password []byte, salt []byte) []byte {
	return argon2.IDKey(password, salt, ArgonTime, ArgonMem, ArgonThrds, KeyLen)
}

// GenerateSalt returns [SaltLen] cryptographically random bytes.
// Fresh salt for every derivation — no repeats, no patterns, ever.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("salt: %w", err)
	}
	return salt, nil
}
