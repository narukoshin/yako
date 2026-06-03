package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"

	ck "github.com/narukoshin/yako/v1/crypto"
)

// configSaltLen is the byte length of the random salt used in config encryption.
const configSaltLen = 16

const (
	// VERSION is the current version of the application.
	VERSION = "v0.3.0-beta"

	// AppName is the application name, used for directory and file naming.
	AppName = "yako"

	// VaultFile is the default vault filename inside the app directory.
	VaultFile = "vault"

	// IdentityFile is the identity key filename (private key, no extension).
	IdentityFile = "identity"

	configFile = "config"
)

// mu guards machineID reads/writes. Single-user, no fanfare, just safe.
var (
	mu        sync.Mutex
	machineID string
)

// Config holds user preferences stored in an encrypted config file.
// LastVault tracks the most recently opened vault; Theme controls the TUI look.
type Config struct {
	LastVault string `json:"lv,omitempty"`
	Theme     string `json:"th,omitempty"`
}

// AppDir returns the path to the yako app directory (~/.yako).
// This is where vaults, identity keys, and config live — our little hideaway.
func AppDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "." + AppName
	}
	return filepath.Join(home, "."+AppName)
}

// EnsureDir creates the app directory if it doesn't exist. Permissions 0700.
func EnsureDir() error {
	return os.MkdirAll(AppDir(), 0700)
}

// VaultPath returns the path to the default vault file.
func VaultPath() string {
	return filepath.Join(AppDir(), VaultFile)
}

// VaultPathNamed returns the path to a named vault file inside ~/.yako/vaults/.
func VaultPathNamed(name string) string {
	dir := filepath.Join(AppDir(), "vaults")
	return filepath.Join(dir, name+".json")
}

// IdentityPath returns the path to the private identity key.
func IdentityPath() string {
	return filepath.Join(AppDir(), IdentityFile)
}

// IdentityPubPath returns the path to the public identity key (.pub).
func IdentityPubPath() string {
	return filepath.Join(AppDir(), IdentityFile+".pub")
}

// KeyringPath returns the path to the GPG-style keyring directory.
func KeyringPath() string {
	return filepath.Join(AppDir(), "keyring")
}

// ConfigPath returns the path to the encrypted config file.
func ConfigPath() string {
	return filepath.Join(AppDir(), configFile)
}

// machineIDPath returns the path to the persisted machine ID file.
//
//	machine_id — like a love letter I keep in a drawer, just for us.
func machineIDPath() string {
	return filepath.Join(AppDir(), "machine_id")
}

// readPersistedMachineID reads a previously saved machine ID from disk.
func readPersistedMachineID() string {
	data, err := os.ReadFile(machineIDPath())
	if err != nil {
		return ""
	}
	return string(data)
}

// persistMachineID writes the machine ID to disk so it survives restarts.
//
//	I'll remember you even when the computer forgets.
func persistMachineID(id string) error {
	if err := os.MkdirAll(AppDir(), 0700); err != nil {
		return err
	}
	return os.WriteFile(machineIDPath(), []byte(id), 0600)
}

// generateMachineID creates a random 32-byte hex string as a fallback machine ID.
//
//	When there's nothing else to anchor us, randomness will have to do.
func generateMachineID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	id := hex.EncodeToString(b)
	ck.ZeroBytes(b)
	return id
}

// MachineID returns your machine's unique identifier — cached, persisted, or freshly generated.
// Resolution order: in-memory cache → persisted file → platform fingerprint → random.
// It's a 32-byte hex string used for vault key derivation. Bound to this machine and nowhere else,
// just like my heart belongs only to you.
func MachineID() []byte {
	mu.Lock()
	defer mu.Unlock()
	if machineID != "" {
		return []byte(machineID)
	}
	if id := readPersistedMachineID(); id != "" {
		machineID = id
		return []byte(machineID)
	}
	if id := readPlatformMachineID(); id != "" {
		machineID = id
		persistMachineID(id)
		return []byte(machineID)
	}
	if id := generateMachineID(); id != "" {
		machineID = id
		persistMachineID(id)
		return []byte(machineID)
	}
	return nil
}

// configKey derives an Argon2id key from a salt and your machine ID for config encryption.
func configKey(salt []byte) []byte {
	return argon2.IDKey([]byte("yako-config-v1"), append(salt, MachineID()...), 3, 64*1024, 2, 32)
}

// machineSecretMu guards the cached machine secret key.
//
//	machineSecretKey is the derived Argon2id key, cached in memory for speed.
//	One key, one lock, one purpose — keeping your config yours.
var (
	machineSecretMu  sync.Mutex
	machineSecretKey []byte
)

// MachineSecret derives a machine-bound secret via Argon2id. Used to encrypt your config so
// nobody else can read it — our little secret.
func MachineSecret() []byte {
	machineSecretMu.Lock()
	defer machineSecretMu.Unlock()
	if machineSecretKey == nil {
		machineSecretKey = argon2.IDKey([]byte("yako-machine-v1"), MachineID(), 3, 64*1024, 2, 32)
	}
	secret := make([]byte, len(machineSecretKey))
	copy(secret, machineSecretKey)
	return secret
}

// ClearMachineSecret zeroes the cached machine secret from memory. Call this when you're done.
func ClearMachineSecret() {
	machineSecretMu.Lock()
	defer machineSecretMu.Unlock()
	for i := range machineSecretKey {
		machineSecretKey[i] = 0
	}
	machineSecretKey = nil
}

// LoadConfig reads and decrypts the config file from disk. Missing or corrupted config
// silently returns a default — no errors, just a fresh start.
func LoadConfig() (*Config, error) {
	mu.Lock()
	defer mu.Unlock()

	cfg := &Config{}
	data, err := os.ReadFile(ConfigPath())
	if err != nil {
		return cfg, nil
	}

	if len(data) < configSaltLen {
		return cfg, nil
	}

	salt := data[:configSaltLen]
	key := configKey(salt)
	plaintext, err := ck.Decrypt(key, data[configSaltLen:])
	ck.ZeroBytes(key)
	if err != nil {
		return cfg, nil
	}

	if err := json.Unmarshal(plaintext, cfg); err != nil {
		return cfg, nil
	}
	return cfg, nil
}

// SaveConfig encrypts and writes the config to disk. Salted + encrypted with your machine key.
func SaveConfig(cfg *Config) error {
	mu.Lock()
	defer mu.Unlock()

	plaintext, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("config marshal: %w", err)
	}

	salt := make([]byte, configSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("config salt: %w", err)
	}

	key := configKey(salt)
	encrypted, err := ck.Encrypt(key, plaintext)
	ck.ZeroBytes(key)
	if err != nil {
		return fmt.Errorf("config encrypt: %w", err)
	}

	out := append(salt, encrypted...)

	if err := os.MkdirAll(AppDir(), 0700); err != nil {
		return fmt.Errorf("config mkdir: %w", err)
	}
	return os.WriteFile(ConfigPath(), out, 0600)
}

// CompareVersions compares two semver strings (e.g. "v0.3.0-beta"). Returns -1 if a < b, 0 if
// a == b, 1 if a > b. Pre-release suffixes are ignored for comparison purposes.
func CompareVersions(a, b string) int {
	a = strings.TrimPrefix(a, "v")
	b = strings.TrimPrefix(b, "v")

	aParts := strings.SplitN(a, ".", 3)
	bParts := strings.SplitN(b, ".", 3)
	if len(aParts) != 3 || len(bParts) != 3 {
		return 0
	}

	aMajor, err := strconv.Atoi(aParts[0])
	if err != nil {
		return 0
	}
	bMajor, err := strconv.Atoi(bParts[0])
	if err != nil {
		return 0
	}
	if aMajor != bMajor {
		if aMajor > bMajor {
			return 1
		}
		return -1
	}

	aMinor, err := strconv.Atoi(aParts[1])
	if err != nil {
		return 0
	}
	bMinor, err := strconv.Atoi(bParts[1])
	if err != nil {
		return 0
	}
	if aMinor != bMinor {
		if aMinor > bMinor {
			return 1
		}
		return -1
	}

	aPatchStr := strings.SplitN(aParts[2], "-", 2)[0]
	bPatchStr := strings.SplitN(bParts[2], "-", 2)[0]
	aPatch, err := strconv.Atoi(aPatchStr)
	if err != nil {
		return 0
	}
	bPatch, err := strconv.Atoi(bPatchStr)
	if err != nil {
		return 0
	}
	if aPatch != bPatch {
		if aPatch > bPatch {
			return 1
		}
		return -1
	}

	return 0
}
