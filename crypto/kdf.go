package crypto

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	SaltLen    = 16
	KeyLen     = 32
	ArgonTime  = 3
	ArgonMem   = 128 * 1024
	ArgonThrds = 4
)

func DeriveKey(password []byte, salt []byte) []byte {
	return argon2.IDKey(password, salt, ArgonTime, ArgonMem, ArgonThrds, KeyLen)
}

func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("salt: %w", err)
	}
	return salt, nil
}
