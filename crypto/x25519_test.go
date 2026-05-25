package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateKeypair(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if len(priv) != PrivateKeySize {
		t.Fatalf("private key length: got %d, want %d", len(priv), PrivateKeySize)
	}
	if len(pub) != PublicKeySize {
		t.Fatalf("public key length: got %d, want %d", len(pub), PublicKeySize)
	}
}

func TestSharedSecretConsistency(t *testing.T) {
	alicePriv, alicePub, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("Alice keygen: %v", err)
	}

	bobPriv, bobPub, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("Bob keygen: %v", err)
	}

	aliceShared, err := SharedSecret(alicePriv, bobPub)
	if err != nil {
		t.Fatalf("Alice shared: %v", err)
	}

	bobShared, err := SharedSecret(bobPriv, alicePub)
	if err != nil {
		t.Fatalf("Bob shared: %v", err)
	}

	if !bytes.Equal(aliceShared, bobShared) {
		t.Fatal("shared secrets should be equal")
	}
}

func TestEncryptDecryptAsymmetricRoundtrip(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	plaintext := []byte("secret message for the key owner")

	ct, err := EncryptAsymmetric(pub, plaintext)
	if err != nil {
		t.Fatalf("EncryptAsymmetric: %v", err)
	}

	got, err := DecryptAsymmetric(priv, ct)
	if err != nil {
		t.Fatalf("DecryptAsymmetric: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Fatalf("got %q, want %q", got, plaintext)
	}
}

func TestEncryptAsymmetricWrongRecipient(t *testing.T) {
	alicePriv, _, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("Alice keygen: %v", err)
	}

	_, bobPub, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("Bob keygen: %v", err)
	}

	ct, err := EncryptAsymmetric(bobPub, []byte("secret"))
	if err != nil {
		t.Fatalf("EncryptAsymmetric: %v", err)
	}

	_, err = DecryptAsymmetric(alicePriv, ct)
	if err == nil {
		t.Fatal("expected error: Alice should not decrypt Bob's message")
	}
}

func TestDecryptAsymmetricShortCiphertext(t *testing.T) {
	priv, _, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	_, err = DecryptAsymmetric(priv, make([]byte, 16))
	if err == nil {
		t.Fatal("expected error for short ciphertext")
	}
}

func TestEncryptAsymmetricProducesUniqueOutput(t *testing.T) {
	_, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	msg := []byte("same message")

	ct1, err := EncryptAsymmetric(pub, msg)
	if err != nil {
		t.Fatalf("Encrypt 1: %v", err)
	}

	ct2, err := EncryptAsymmetric(pub, msg)
	if err != nil {
		t.Fatalf("Encrypt 2: %v", err)
	}

	if bytes.Equal(ct1, ct2) {
		t.Fatal("two encryptions produced identical output (ephemeral key reuse)")
	}
}

func TestFingerprintConsistency(t *testing.T) {
	_, pub1, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("keygen 1: %v", err)
	}

	_, pub2, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("keygen 2: %v", err)
	}

	fp1 := Fingerprint(pub1)
	fp2 := Fingerprint(pub2)

	if fp1 == fp2 {
		t.Fatal("different keys should have different fingerprints")
	}

	if Fingerprint(pub1) != Fingerprint(pub1) {
		t.Fatal("same key should have consistent fingerprint")
	}
}
