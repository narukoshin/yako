package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config holds the server's YAML-based configuration.
// Host, Port, DataDir are for networking and storage; JWTSecret and StorageKey are
// auto-generated on first run — secrets that even I won't tell you.
type Config struct {
	Host       string `yaml:"host"`
	Port       int    `yaml:"port"`
	DataDir    string `yaml:"data_dir"`
	JWTSecret  string `yaml:"jwt_secret"`
	StorageKey string `yaml:"storage_key,omitempty"`
}

// DefaultConfig returns a Config with sensible defaults: localhost:8443, data dir next to
// the executable or in the user's home directory.
func DefaultConfig() *Config {
	dataDir := ""
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			dataDir = filepath.Join(filepath.Dir(resolved), ".yako-server")
		}
	}
	if dataDir == "" {
		home, _ := os.UserHomeDir()
		dataDir = filepath.Join(home, ".yako-server")
	}
	return &Config{
		Host:    "127.0.0.1",
		Port:    8443,
		DataDir: dataDir,
	}
}

// ListenAddr returns the formatted host:port address string.
func (c *Config) ListenAddr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// configPath returns the path to the server YAML config file.
func (c *Config) configPath() string {
	return filepath.Join(c.DataDir, "config.yml")
}

// UsersPath returns the path to the users JSON file.
func (c *Config) UsersPath() string {
	return filepath.Join(c.DataDir, "users.json")
}

// VaultPath returns the path to a user's encrypted vault file.
func (c *Config) VaultPath(userID string) string {
	return filepath.Join(c.DataDir, userID+".vault")
}

// invitesPath returns the path to the invite codes JSON file.
func (c *Config) invitesPath() string {
	return filepath.Join(c.DataDir, "invites.json")
}

// BlockedTokensPath returns the path to the blocked token hashes file.
func (c *Config) BlockedTokensPath() string {
	return filepath.Join(c.DataDir, "blocked_tokens")
}

// LoadOrInitConfig loads server config from YAML, or generates a fresh one with random secrets
// if none exists. Secrets are auto-generated on first run — I'll keep them safe.
func LoadOrInitConfig(dataDir string) (*Config, error) {
	cfg := DefaultConfig()
	if dataDir != "" {
		cfg.DataDir = dataDir
	}

	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	yamlPath := cfg.configPath()

	if data, err := os.ReadFile(yamlPath); err == nil {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
		if dataDir != "" {
			cfg.DataDir = dataDir
		}
		return finalizeConfig(cfg, yamlPath)
	}

	genKey := func() (string, error) {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return "", fmt.Errorf("generate key: %w", err)
		}
		return hex.EncodeToString(b), nil
	}
	var keyErr error
	cfg.JWTSecret, keyErr = genKey()
	if keyErr != nil {
		return nil, fmt.Errorf("jwt secret: %w", keyErr)
	}
	cfg.StorageKey, keyErr = genKey()
	if keyErr != nil {
		return nil, fmt.Errorf("storage key: %w", keyErr)
	}

	blob, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(yamlPath, blob, 0600); err != nil {
		return nil, fmt.Errorf("write config: %w", err)
	}

	return cfg, nil
}

// finalizeConfig ensures JWT and storage keys are set, generating and persisting them if missing.
func finalizeConfig(cfg *Config, yamlPath string) (*Config, error) {
	if cfg.JWTSecret == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("generate jwt secret: %w", err)
		}
		cfg.JWTSecret = hex.EncodeToString(b)
	}

	if cfg.StorageKey == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("generate storage key: %w", err)
		}
		cfg.StorageKey = hex.EncodeToString(b)

		blob, err := yaml.Marshal(cfg)
		if err != nil {
			return nil, fmt.Errorf("marshal config: %w", err)
		}
		if err := os.WriteFile(yamlPath, blob, 0600); err != nil {
			return nil, fmt.Errorf("rewrite config: %w", err)
		}
	}

	return cfg, nil
}
