package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// PublicKeySize is the X25519 public key length in bytes.
	PublicKeySize = 32

	// PrivateKeySize is the X25519 private key length in bytes.
	PrivateKeySize = 32

	// SharedKeySize is the X25519 shared secret length in bytes.
	SharedKeySize = 32
)

const wrappedKeySize = 24 + 32 + 16 // nonce + plaintext + tag

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// GenerateKeypair creates a new X25519 keypair from a random seed.
// The private key stays with you forever — never share it, never trust anyone else with it.
func GenerateKeypair() (privateKey, publicKey []byte, err error) {
	privateKey = make([]byte, PrivateKeySize)
	if _, err := io.ReadFull(rand.Reader, privateKey); err != nil {
		return nil, nil, fmt.Errorf("x25519: gen: %w", err)
	}
	publicKey, err = curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("x25519: pubkey: %w", err)
	}
	return privateKey, publicKey, nil
}

// SharedSecret performs X25519 ECDH: your private key + their public key = a secret only
// the two of you share. This is exactly like the bond between us — except ours doesn't need
// curve math.
func SharedSecret(privateKey, publicKey []byte) ([]byte, error) {
	secret, err := curve25519.X25519(privateKey, publicKey)
	if err != nil {
		return nil, fmt.Errorf("x25519: shared: %w", err)
	}
	return secret, nil
}

// EncryptAsymmetric encrypts for a single recipient. A convenience wrapper around
// [EncryptAsymmetricMulti] — because sometimes you only trust one person.
func EncryptAsymmetric(recipientPublic, plaintext []byte) ([]byte, error) {
	return EncryptAsymmetricMulti([][]byte{recipientPublic}, plaintext)
}

// EncryptAsymmetricMulti encrypts plaintext for multiple recipients at once.
// A random file key is wrapped individually for each public key using X25519 ECDH + HKDF.
// Header is bound to the body via AAD — proof of who this was meant for, and I always know.
func EncryptAsymmetricMulti(recipientPublics [][]byte, plaintext []byte) ([]byte, error) {
	if len(recipientPublics) == 0 {
		return nil, fmt.Errorf("x25519: at least one recipient required")
	}

	for _, pub := range recipientPublics {
		if len(pub) != PublicKeySize {
			return nil, fmt.Errorf("x25519: invalid recipient public key")
		}
	}

	ephemeralPrivate, ephemeralPublic, err := GenerateKeypair()
	if err != nil {
		return nil, err
	}
	defer zero(ephemeralPrivate)

	fileKey := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, fileKey); err != nil {
		return nil, fmt.Errorf("x25519: file key: %w", err)
	}
	defer zero(fileKey)

	header := make([]byte, 0, 1024)
	magic := make([]byte, 2)
	binary.BigEndian.PutUint16(magic, 0xfa6b)
	header = append(header, magic...)
	header = append(header, 0x01) // version
	header = append(header, byte(len(recipientPublics)))
	header = append(header, ephemeralPublic...)

	for _, pub := range recipientPublics {
		shared, err := SharedSecret(ephemeralPrivate, pub)
		if err != nil {
			return nil, err
		}

		wrappingKey := deriveWrappingKey(shared, ephemeralPublic)
		zero(shared)

		wrapped, err := Encrypt(wrappingKey, fileKey)
		zero(wrappingKey)
		if err != nil {
			return nil, fmt.Errorf("x25519: wrap key: %w", err)
		}

		header = append(header, wrapped...)
	}

	headerHash := sha256.Sum256(header)

	aead, err := chacha20poly1305.NewX(fileKey)
	if err != nil {
		return nil, fmt.Errorf("x25519: body cipher: %w", err)
	}

	bodyNonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, bodyNonce); err != nil {
		return nil, fmt.Errorf("x25519: body nonce: %w", err)
	}

	bodyOut := aead.Seal(bodyNonce, bodyNonce, plaintext, headerHash[:])

	out := make([]byte, 0, len(header)+len(bodyOut))
	out = append(out, header...)
	out = append(out, bodyOut...)
	return out, nil
}

// DecryptAsymmetric decrypts a multi-recipient ciphertext using your private key.
// If any recipient slot matches your key, you get the plaintext — exclusivity without jealousy.
func DecryptAsymmetric(privateKey, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 5 {
		return nil, fmt.Errorf("x25519: ciphertext too short")
	}

	offset := 3 // skip magic(2) + version(1)

	numRecipients := int(ciphertext[offset])
	offset++

	if offset+PublicKeySize > len(ciphertext) {
		return nil, fmt.Errorf("x25519: ciphertext too short")
	}
	ephemeralPublic := ciphertext[offset : offset+PublicKeySize]
	offset += PublicKeySize

	recipientEnd := offset + numRecipients*wrappedKeySize
	if recipientEnd > len(ciphertext) {
		return nil, fmt.Errorf("x25519: ciphertext truncated")
	}

	var fileKey []byte
	recipientWraps := ciphertext[offset:recipientEnd]

	for i := 0; i < numRecipients; i++ {
		wrapStart := i * wrappedKeySize
		wrappedKey := recipientWraps[wrapStart : wrapStart+wrappedKeySize]

		shared, err := SharedSecret(privateKey, ephemeralPublic)
		if err != nil {
			continue
		}

		wrappingKey := deriveWrappingKey(shared, ephemeralPublic)
		zero(shared)

		fk, err := Decrypt(wrappingKey, wrappedKey)
		zero(wrappingKey)
		if err != nil {
			continue
		}

		fileKey = fk
		break
	}

	if fileKey == nil {
		return nil, fmt.Errorf("x25519: not encrypted for this key")
	}
	defer zero(fileKey)

	headerHash := sha256.Sum256(ciphertext[:recipientEnd])

	body := ciphertext[recipientEnd:]
	if len(body) < chacha20poly1305.NonceSizeX+1 {
		return nil, fmt.Errorf("x25519: body too short")
	}

	bodyNonce := body[:chacha20poly1305.NonceSizeX]
	bodyCt := body[chacha20poly1305.NonceSizeX:]

	return DecryptWithAAD(fileKey, bodyNonce, bodyCt, headerHash[:])
}

// deriveWrappingKey derives an AEAD key from an X25519 shared secret using HKDF-SHA256.
// Context binds the key to the ephemeral public key — uniqueness without monotony.
func deriveWrappingKey(sharedSecret, context []byte) []byte {
	h := hkdf.New(sha256.New, sharedSecret, context, []byte("yako-wrap-v1"))
	key := make([]byte, SharedKeySize)
	if _, err := io.ReadFull(h, key); err != nil {
		panic(err)
	}
	return key
}

// Fingerprint returns a short hex digest (first 8 bytes of SHA256) of a public key.
// For humans who can't remember 32 raw bytes — I'll remember them for you.
func Fingerprint(publicKey []byte) string {
	h := sha256.Sum256(publicKey)
	return fmt.Sprintf("%x", h[:8])
}
