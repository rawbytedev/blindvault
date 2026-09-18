package service

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/rawbytedev/blindvault/pkg/securememory"
	"github.com/rs/zerolog/log"
)

// Config holds all service-level configuration.
type Config struct {
	// Server settings
	ListenAddr string `yaml:"listen_addr" env:"LISTEN_ADDR" default:":8080"`

	// Crypto settings
	MasterSeedEnclave *securememory.Enclave `yaml:"-" json:"-"`
	MasterSeedHex     string                `yaml:"master_seed_hex" env:"MASTER_SEED_HEX"` // insecure
	ActiveEpoch       string                `yaml:"active_epoch" env:"ACTIVE_EPOCH" default:"2026-01"`
	SupportedEpochs   []string              `yaml:"supported_epochs" env:"SUPPORTED_EPOCHS"` // e.g., ["2026-01", "2025-12"]
	DST               string                `yaml:"dst" env:"DST" default:"BCIS-V1-MESSAGE"` // For HashToCurve

	// Authentication
	AuthSecret string `yaml:"auth_secret" env:"AUTH_SECRET"`
	// Storage
	RedisAddr       string `yaml:"redis_addr" env:"REDIS_ADDR"`
	RedisPassword   string `yaml:"redis_password" env:"REDIS_PASSWORD"`
	RedisDB         int    `yaml:"redis_db" env:"REDIS_DB" default:"0"`
	RedisExpiration int    `yaml:"redis_expiration" env:"REDIS_EXPIRATION" default:"2592000"` // 30 days in seconds
	// revocation storage
	RevocationRedisAddr     string `yaml:"revocation_redis_addr" env:"REVOCATION_REDIS_ADDR"`
	RevocationRedisPassword string `yaml:"revocation_redis_password" env:"REVOCATION_REDIS_PASSWORD"`
	RevocationRedisDB       int    `yaml:"revocation_redis_db" env:"REVOCATION_REDIS_DB" default:"1"`
	// Use in-memory store (for testing only)
	UseMemoryStore bool `yaml:"use_memory_store" env:"USE_MEMORY_STORE" default:"false"`
	RateLimitBurst int  `yaml:"rate_limit_burst" env:"RATE_LIMIT_BURST" default:"20"`
	RateLimit      int  `yaml:"rate_limit_requests" env:"RATE_LIMIT_REQUESTS" default:"100"`
	UseDemo        bool `yaml:"use_demo" env:"USE_DEMO" default:"true"`
}

// Validate checks required fields.
func (c *Config) Validate() error {
	if c.MasterSeedEnclave == nil && c.MasterSeedHex == "" {
		return fmt.Errorf("master_seed_hex is required")
	}
	if c.MasterSeedEnclave != nil {
		buff, err := c.MasterSeedEnclave.Open()
		if err != nil {
			return fmt.Errorf("LockedBuffer is nil")
		}
		defer buff.Close()

		if len(buff.Bytes()) != 32 {
			return fmt.Errorf("master_seed decoded length must be 32 bytes (64 hex characters)")
		}
	} else {
		if len(c.MasterSeedHex) != 64 {
			return fmt.Errorf("master_seed_hex must be 64 hex characters (32 bytes)")
		}
	}
	if c.ActiveEpoch == "" {
		return fmt.Errorf("active_epoch is required")
	}
	if len(c.SupportedEpochs) == 0 {
		// If not specified, use active epoch only
		c.SupportedEpochs = []string{c.ActiveEpoch}
	}
	if !c.UseMemoryStore {
		if c.RedisAddr == "" {
			return fmt.Errorf("redis_addr must be provided")
		}
	}
	if c.AuthSecret == "" {
		return fmt.Errorf("auth_secret is required")
	}
	return nil
}

func (c *Config) ApplyEnvOverrides() {
	if seed := os.Getenv("BLINDVAULT_MASTER_SEED_HEX"); seed != "" {
		c.MasterSeedHex = seed
	} else if seed := os.Getenv("MASTER_SEED_HEX"); seed != "" {
		c.MasterSeedHex = seed
	}
	if epoch := os.Getenv("ACTIVE_EPOCH"); epoch != "" {
		c.ActiveEpoch = epoch
	}
	if values := os.Getenv("SUPPORTED_EPOCHS"); values != "" {
		c.SupportedEpochs = strings.Split(values, ",")
		for i := range c.SupportedEpochs {
			c.SupportedEpochs[i] = strings.TrimSpace(c.SupportedEpochs[i])
		}
	}
	if dst := os.Getenv("DST"); dst != "" {
		c.DST = dst
	}
	if secret := os.Getenv("AUTH_SECRET"); secret != "" {
		c.AuthSecret = secret
	}
	if addr := os.Getenv("LISTEN_ADDR"); addr != "" {
		c.ListenAddr = addr
	}
	if addr := os.Getenv("REDIS_ADDR"); addr != "" {
		c.RedisAddr = addr
	}
	if password := os.Getenv("REDIS_PASSWORD"); password != "" {
		c.RedisPassword = password
	}
	if db := os.Getenv("REDIS_DB"); db != "" {
		if parsed, err := strconv.Atoi(db); err == nil {
			c.RedisDB = parsed
		}
	}
	if expiration := os.Getenv("REDIS_EXPIRATION"); expiration != "" {
		if parsed, err := strconv.Atoi(expiration); err == nil {
			c.RedisExpiration = parsed
		}
	}
	if addr := os.Getenv("REVOCATION_REDIS_ADDR"); addr != "" {
		c.RevocationRedisAddr = addr
	}
	if password := os.Getenv("REVOCATION_REDIS_PASSWORD"); password != "" {
		c.RevocationRedisPassword = password
	}
	if db := os.Getenv("REVOCATION_REDIS_DB"); db != "" {
		if parsed, err := strconv.Atoi(db); err == nil {
			c.RevocationRedisDB = parsed
		}
	}
	if value := os.Getenv("USE_MEMORY_STORE"); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			c.UseMemoryStore = parsed
		}
	}
	if value := os.Getenv("USE_DEMO"); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			c.UseDemo = parsed
		}
	}
	if burst := os.Getenv("RATE_LIMIT_BURST"); burst != "" {
		if parsed, err := strconv.Atoi(burst); err == nil {
			c.RateLimitBurst = parsed
		}
	}
	if rate := os.Getenv("RATE_LIMIT_REQUESTS"); rate != "" {
		if parsed, err := strconv.Atoi(rate); err == nil {
			c.RateLimit = parsed
		}
	}
}

func (c *Config) LoadMasterSeed() error {
	var seedHex string
	var source string

	// 1. Prefer explicit environment variables, with BLINDVAULT_* taking precedence.
	if envSeed := os.Getenv("BLINDVAULT_MASTER_SEED_HEX"); envSeed != "" {
		seedHex = envSeed
		source = "BLINDVAULT_MASTER_SEED_HEX"
	} else if seedFile := os.Getenv("BLINDVAULT_SEED_FILE"); seedFile != "" {
		// 2. Try secret file.
		data, err := os.ReadFile(seedFile)
		if err != nil {
			return fmt.Errorf("failed to read seed file %s: %w", seedFile, err)
		}
		seedHex = strings.TrimSpace(string(data))
		source = "BLINDVAULT_SEED_FILE"
		// Zero the file buffer
		for i := range data {
			data[i] = 0
		}
	} else if envSeed := os.Getenv("MASTER_SEED_HEX"); envSeed != "" {
		seedHex = envSeed
		source = "MASTER_SEED_HEX (legacy compatibility)"
	} else if c.MasterSeedHex != "" {
		// 3. Fallback to YAML config.
		seedHex = c.MasterSeedHex
		source = "config.yaml (deprecated)"
		log.Warn().Msg("Loading master seed from config.yaml is insecure and deprecated!")
		c.MasterSeedHex = ""
	} else {
		return fmt.Errorf("master seed not found in env, file, or config")
	}

	seedBytes, err := hex.DecodeString(seedHex)
	if err != nil {
		return fmt.Errorf("invalid master seed format: %w", err)
	}
	if len(seedBytes) != 32 {
		return fmt.Errorf("master seed must be 32 bytes (64 hex characters)")
	}
	// Seal it into an Enclave
	c.MasterSeedEnclave = securememory.NewEnclaveFromBytes(seedBytes)

	for i := range seedBytes {
		seedBytes[i] = 0
	}

	log.Info().Str("source", source).Msg("Master seed loaded and sealed")
	return nil
}

// MasterSeed returns the decoded master seed.
func (c *Config) MasterSeed() (*securememory.Enclave, error) {
	if c.MasterSeedEnclave != nil {
		return c.MasterSeedEnclave, nil
	}
	if c.MasterSeedHex != "" {
		seed, err := hex.DecodeString(c.MasterSeedHex)
		if err != nil {
			return nil, fmt.Errorf("Unable to deserialize masterseed from Config: %w", err)
		}
		if len(seed) != 32 {
			return nil, fmt.Errorf("master seed must be 32 bytes (64 hex characters)")
		}
		c.MasterSeedEnclave = securememory.NewEnclaveFromBytes(seed)
		return c.MasterSeedEnclave, nil
	}
	return nil, fmt.Errorf("Master seed not loaded")
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
