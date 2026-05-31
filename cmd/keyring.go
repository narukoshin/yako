package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/narukoshin/yako/v1/config"
	ck "github.com/narukoshin/yako/v1/crypto"
	"github.com/narukoshin/yako/v1/kerr"
)

// keyringEntry is a single entry in the GPG-style keyring: name, base64 public key, and fingerprint.
type keyringEntry struct {
	Name        string `json:"name"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
}

// keyring is the collection of imported public keys, persisted as JSON.
type keyring struct {
	Keys []keyringEntry `json:"keys"`
}

// loadKeyring reads the keyring from disk. Returns an empty keyring if the file doesn't exist.
func loadKeyring() (*keyring, error) {
	data, err := os.ReadFile(config.KeyringPath())
	if err != nil {
		if os.IsNotExist(err) {
			return &keyring{}, nil
		}
		return nil, fmt.Errorf("read keyring: %w", err)
	}

	var kr keyring
	if err := json.Unmarshal(data, &kr); err != nil {
		return nil, fmt.Errorf("parse keyring: %w", err)
	}
	return &kr, nil
}

// saveKeyring serializes and writes the keyring to disk as indented JSON.
func saveKeyring(kr *keyring) error {
	data, err := json.MarshalIndent(kr, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal keyring: %w", err)
	}
	if err := os.MkdirAll(config.AppDir(), 0700); err != nil {
		return err
	}
	return os.WriteFile(config.KeyringPath(), data, 0600)
}

// lookupKey finds a public key in the keyring by name and returns the raw 32-byte key.
func lookupKey(name string) ([]byte, error) {
	kr, err := loadKeyring()
	if err != nil {
		return nil, err
	}
	for _, k := range kr.Keys {
		if k.Name == name {
			pub, err := base64.StdEncoding.DecodeString(k.PublicKey)
			if err != nil {
				return nil, kerr.ErrCorrupted
			}
			return pub, nil
		}
	}
	return nil, kerr.ErrKeyNotFound(name)
}

// addToKeyring adds a public key to the keyring under the given name. Checks for duplicates
//
//	and sorts alphabetically after insertion. Like organizing my bookshelf — everything has its place.
func addToKeyring(name string, pub []byte) error {
	kr, err := loadKeyring()
	if err != nil {
		return err
	}

	for _, k := range kr.Keys {
		if k.Name == name {
			return kerr.ErrKeyExists(name)
		}
	}

	kr.Keys = append(kr.Keys, keyringEntry{
		Name:        name,
		PublicKey:   base64.StdEncoding.EncodeToString(pub),
		Fingerprint: ck.Fingerprint(pub),
	})

	sort.Slice(kr.Keys, func(i, j int) bool {
		return kr.Keys[i].Name < kr.Keys[j].Name
	})

	return saveKeyring(kr)
}

// removeFromKeyring deletes a key from the keyring by name. Returns [ErrKeyNotFound] if not found.
func removeFromKeyring(name string) error {
	kr, err := loadKeyring()
	if err != nil {
		return err
	}

	found := false
	for i, k := range kr.Keys {
		if k.Name == name {
			kr.Keys = append(kr.Keys[:i], kr.Keys[i+1:]...)
			found = true
			break
		}
	}
	if !found {
		return kerr.ErrKeyNotFound(name)
	}

	return saveKeyring(kr)
}

// resolveRecipient resolves a recipient string: first tries base64 decode (for raw pubkey),
//
//	then looks up the keyring by name. First match wins — I don't like ambiguity.
func resolveRecipient(value string) ([]byte, error) {
	pub, err := base64.StdEncoding.DecodeString(value)
	if err == nil && len(pub) == 32 {
		return pub, nil
	}

	pub, err = lookupKey(value)
	if err != nil {
		return nil, fmt.Errorf("not a valid base64 key and no keyring entry found for %q", value)
	}
	return pub, nil
}
