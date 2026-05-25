package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/argon2"

	ck "github.com/narukoshin/yako/v1/crypto"
)

const configSaltLen = 16

const (
	// VERSION is the current version of the application.
	VERSION	     = "v0.2.3-beta"

	AppName      = "yako"
	VaultFile    = "vault"
	IdentityFile = "identity"
	configFile   = "config"
)

var (
	mu        sync.Mutex
	machineID string
)

type Config struct {
	LastVault string `json:"lv,omitempty"`
	Theme     string `json:"th,omitempty"`
}

func AppDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "." + AppName
	}
	return filepath.Join(home, "."+AppName)
}

func EnsureDir() error {
	return os.MkdirAll(AppDir(), 0700)
}

func VaultPath() string {
	return filepath.Join(AppDir(), VaultFile)
}

func VaultPathNamed(name string) string {
	dir := filepath.Join(AppDir(), "vaults")
	return filepath.Join(dir, name+".json")
}

func IdentityPath() string {
	return filepath.Join(AppDir(), IdentityFile)
}

func IdentityPubPath() string {
	return filepath.Join(AppDir(), IdentityFile+".pub")
}

func ConfigPath() string {
	return filepath.Join(AppDir(), configFile)
}

func machineIDPath() string {
	return filepath.Join(AppDir(), "machine_id")
}

func readPersistedMachineID() string {
	data, err := os.ReadFile(machineIDPath())
	if err != nil {
		return ""
	}
	return string(data)
}

func persistMachineID(id string) error {
	if err := os.MkdirAll(AppDir(), 0700); err != nil {
		return err
	}
	return os.WriteFile(machineIDPath(), []byte(id), 0600)
}

func generateMachineID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

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

func configKey(salt []byte) []byte {
	return argon2.IDKey([]byte("yako-config-v1"), append(salt, MachineID()...), 3, 64*1024, 2, 32)
}

var (
	machineSecretMu  sync.Mutex
	machineSecretKey []byte
)

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

func ClearMachineSecret() {
	machineSecretMu.Lock()
	defer machineSecretMu.Unlock()
	for i := range machineSecretKey {
		machineSecretKey[i] = 0
	}
	machineSecretKey = nil
}

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
	if err != nil {
		return cfg, nil
	}

	if err := json.Unmarshal(plaintext, cfg); err != nil {
		return cfg, nil
	}
	return cfg, nil
}

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
	if err != nil {
		return fmt.Errorf("config encrypt: %w", err)
	}

	out := append(salt, encrypted...)

	if err := os.MkdirAll(AppDir(), 0700); err != nil {
		return fmt.Errorf("config mkdir: %w", err)
	}
	return os.WriteFile(ConfigPath(), out, 0600)
}
