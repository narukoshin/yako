package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	PublicKeySize  = 32
	PrivateKeySize = 32
	SharedKeySize  = 32
)

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

func SharedSecret(privateKey, publicKey []byte) ([]byte, error) {
	secret, err := curve25519.X25519(privateKey, publicKey)
	if err != nil {
		return nil, fmt.Errorf("x25519: shared: %w", err)
	}
	return secret, nil
}

func EncryptAsymmetric(recipientPublic, plaintext []byte) ([]byte, error) {
	ephemeralPrivate, ephemeralPublic, err := GenerateKeypair()
	if err != nil {
		return nil, err
	}

	shared, err := SharedSecret(ephemeralPrivate, recipientPublic)
	if err != nil {
		return nil, err
	}

	key := deriveSymmetricKey(shared, ephemeralPublic)

	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		return nil, err
	}

	result := make([]byte, 0, PublicKeySize+len(ciphertext))
	result = append(result, ephemeralPublic...)
	result = append(result, ciphertext...)
	return result, nil
}

func DecryptAsymmetric(privateKey, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < PublicKeySize {
		return nil, fmt.Errorf("x25519: ciphertext too short")
	}

	ephemeralPublic := ciphertext[:PublicKeySize]
	ct := ciphertext[PublicKeySize:]

	shared, err := SharedSecret(privateKey, ephemeralPublic)
	if err != nil {
		return nil, err
	}

	key := deriveSymmetricKey(shared, ephemeralPublic)
	return Decrypt(key, ct)
}

func deriveSymmetricKey(sharedSecret, context []byte) []byte {
	h := hkdf.New(sha256.New, sharedSecret, context, []byte("yako-x25519-v1"))
	key := make([]byte, SharedKeySize)
	if _, err := io.ReadFull(h, key); err != nil {
		panic(err)
	}
	return key
}

func Fingerprint(publicKey []byte) string {
	h := sha256.Sum256(publicKey)
	return fmt.Sprintf("%x", h[:8])
}
