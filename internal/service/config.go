package service

import (
	"encoding/hex"
	"fmt"
)

// Config holds all service-level configuration.
type Config struct {
	// Server settings
	ListenAddr string `yaml:"listen_addr" env:"LISTEN_ADDR" default:":8080"`

	// Crypto settings
	MasterSeedHex   string   `yaml:"master_seed_hex" env:"MASTER_SEED_HEX"`
	ActiveEpoch     string   `yaml:"active_epoch" env:"ACTIVE_EPOCH" default:"2026-01"`
	SupportedEpochs []string `yaml:"supported_epochs" env:"SUPPORTED_EPOCHS"` // e.g., ["2026-01", "2025-12"]
	DST             string   `yaml:"dst" env:"DST" default:"BCIS-V1-MESSAGE"` // For HashToCurve

	// Authentication
	AuthSecret string `yaml:"auth_secret" env:"AUTH_SECRET"`

	// Storage
	RedisAddr       string `yaml:"redis_addr" env:"REDIS_ADDR"`
	RedisPassword   string `yaml:"redis_password" env:"REDIS_PASSWORD"`
	RedisDB         int    `yaml:"redis_db" env:"REDIS_DB" default:"0"`
	RedisExpiration int    `yaml:"redis_expiration" env:"REDIS_EXPIRATION" default:"2592000"` // 30 days in seconds
	// Optional: Use in-memory store (for testing only)
	UseMemoryStore bool `yaml:"use_memory_store" env:"USE_MEMORY_STORE" default:"false"`
}

// Validate checks required fields.
func (c *Config) Validate() error {
	if c.MasterSeedHex == "" {
		return fmt.Errorf("master_seed_hex is required")
	}
	if len(c.MasterSeedHex) != 64 {
		return fmt.Errorf("master_seed_hex must be 64 hex characters (32 bytes)")
	}
	if c.ActiveEpoch == "" {
		return fmt.Errorf("active_epoch is required")
	}
	if len(c.SupportedEpochs) == 0 {
		// If not specified, use active epoch only
		c.SupportedEpochs = []string{c.ActiveEpoch}
	}
	if c.AuthSecret == "" && c.RedisAddr == "" {
		// For production, both should be set, but we allow for dev
	}
	return nil
}

// MasterSeed returns the decoded master seed.
func (c *Config) MasterSeed() ([]byte, error) {
	return hex.DecodeString(c.MasterSeedHex)
}

// DSTBytes returns the DST as bytes.
func (c *Config) DSTBytes() []byte {
	return []byte(c.DST)
}

// IsEpochSupported checks if an epoch is valid for redemption.
func (c *Config) IsEpochSupported(epoch string) bool {
	for _, e := range c.SupportedEpochs {
		if e == epoch {
			return true
		}
	}
	return false
}
