package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Host       string `yaml:"host"`
	Port       int    `yaml:"port"`
	DataDir    string `yaml:"data_dir"`
	JWTSecret  string `yaml:"jwt_secret"`
	StorageKey string `yaml:"storage_key,omitempty"`
}

func DefaultConfig() *Config {
	home, _ := os.UserHomeDir()
	return &Config{
		Host:    "127.0.0.1",
		Port:    8443,
		DataDir: filepath.Join(home, ".yako-server"),
	}
}
func (c *Config) ListenAddr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

func (c *Config) configPath() string {
	return filepath.Join(c.DataDir, "config.yml")
}

func (c *Config) UsersPath() string {
	return filepath.Join(c.DataDir, "users.json")
}

func (c *Config) VaultPath(userID string) string {
	return filepath.Join(c.DataDir, userID+".vault")
}

func (c *Config) invitesPath() string {
	return filepath.Join(c.DataDir, "invites.json")
}

func (c *Config) BlockedTokensPath() string {
	return filepath.Join(c.DataDir, "blocked_tokens")
}

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
