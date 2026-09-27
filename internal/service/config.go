package service

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"errors"

	"github.com/rawbytedev/blindvault/internal/validation"
	"github.com/rawbytedev/blindvault/pkg/logger"
	"github.com/rawbytedev/blindvault/pkg/securememory"
)

type SecretSource string

const (
	SecretSourceInline SecretSource = "inline" // from YAML — dev/test only
	SecretSourceEnv    SecretSource = "env"    // BLINDVAULT_MASTER_SEED_HEX
	SecretSourceFile   SecretSource = "file"   // BLINDVAULT_SEED_FILE
)

// Config holds all service-level configuration.
type Config struct {
	Mode              Mode                  `yaml:"mode" env:"BLINDVAULT_MODE" default:"development"`
	MasterSeedEnclave *securememory.Enclave `yaml:"-" json:"-"`
	MasterSeedHex     string                `yaml:"blindvault_master_seed_hex" env:"BLINDVAULT_MASTER_SEED_HEX"` // insecure
	MasterSeedSource  SecretSource
	// Server settings
	ListenAddr string `yaml:"listen_addr" env:"LISTEN_ADDR" default:":8080"`

	// Crypto settings
	ActiveEpoch     string   `yaml:"active_epoch" env:"ACTIVE_EPOCH" default:"2026-01"`
	SupportedEpochs []string `yaml:"supported_epochs" env:"SUPPORTED_EPOCHS"` // e.g., ["2026-01", "2025-12"]
	DST             string   `yaml:"dst" env:"DST" default:"BCIS-V1-MESSAGE"` // For HashToCurve

	// Authentication
	AuthSecret  string `yaml:"auth_secret" env:"AUTH_SECRET"`
	JWTIssuer   string `yaml:"jwt_issuer" env:"JWT_ISSUER"`
	JWTAudience string `yaml:"jwt_audience" env:"JWT_AUDIENCE"`
	// Storage
	RedisAddr       string `yaml:"redis_addr" env:"REDIS_ADDR"`
	RedisPassword   string `yaml:"redis_password" env:"REDIS_PASSWORD"`
	RedisDB         int    `yaml:"redis_db" env:"REDIS_DB" default:"0"`
	RedisExpiration int    `yaml:"redis_expiration" env:"REDIS_EXPIRATION" default:"2592000"` // 30 days in seconds
	// revocation storage
	RevocationRedisAddr     string `yaml:"revocation_redis_addr" env:"REVOCATION_REDIS_ADDR"`
	RevocationRedisPassword string `yaml:"revocation_redis_password" env:"REVOCATION_REDIS_PASSWORD"`
	RevocationRedisDB       int    `yaml:"revocation_redis_db" env:"REVOCATION_REDIS_DB" default:"1"`
	// ratelimiting
	RateLimitBurst int `yaml:"rate_limit_burst" env:"RATE_LIMIT_BURST" default:"20"`
	RateLimit      int `yaml:"rate_limit_requests" env:"RATE_LIMIT_REQUESTS" default:"100"`
	MaxClients     int `yaml:"max_clients" env:"MAX_CLIENTS" default:"100000"`
	// demo/testing
	UseMemoryStore bool `yaml:"use_memory_store" env:"USE_MEMORY_STORE" default:"false"`
	UseDemo        bool `yaml:"use_demo" env:"USE_DEMO" default:"true"`
}

func (c *Config) ApplyEnvOverrides() {
	if mode := os.Getenv("BLINDVAULT_MODE"); mode != "" {
		c.Mode = Mode(mode)
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
	if issuer := os.Getenv("JWT_ISSUER"); issuer != "" {
		c.JWTIssuer = issuer
	}
	if aud := os.Getenv("JWT_AUDIENCE"); aud != "" {
		c.JWTAudience = aud
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
	if v := os.Getenv("MAX_CLIENTS"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			c.MaxClients = parsed
		}
	}
}

func (c *Config) LoadMasterSeed() error {
	var seedHex string

	switch {
	case os.Getenv("BLINDVAULT_MASTER_SEED_HEX") != "":
		seedHex = os.Getenv("BLINDVAULT_MASTER_SEED_HEX")
		c.MasterSeedSource = SecretSourceEnv

	case os.Getenv("BLINDVAULT_SEED_FILE") != "":
		path := os.Getenv("BLINDVAULT_SEED_FILE")
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read seed file: %w", err)
		}
		seedHex = strings.TrimSpace(string(data))
		for i := range data {
			data[i] = 0
		} // wipe buffer
		c.MasterSeedSource = SecretSourceFile

	case c.MasterSeedHex != "":
		seedHex = c.MasterSeedHex
		c.MasterSeedSource = SecretSourceInline

	default:
		return errors.New("no master seed source configured")
	}

	raw, err := hex.DecodeString(seedHex)
	if err != nil {
		return fmt.Errorf("master seed is not valid hex: %w", err)
	}
	if len(raw) != 32 {
		return fmt.Errorf("master seed must decode to 32 bytes, got %d", len(raw))
	}

	c.MasterSeedEnclave = securememory.NewEnclaveFromBytes(raw)
	for i := range raw {
		raw[i] = 0
	}
	// Clear hex from memory now that it's sealed
	c.MasterSeedHex = ""
	return nil
}

func (c *Config) Validate() error {
	var errs ValidationErrors

	// --- Always required ---
	if !c.Mode.IsValid() {
		errs.Add(fmt.Errorf("mode %q is not one of: development, test, production", c.Mode))
	}
	if c.MasterSeedEnclave == nil {
		errs.Add(errors.New("master seed not loaded; call LoadMasterSeed first"))
	}
	if c.ActiveEpoch == "" {
		errs.Add(errors.New("active_epoch is required"))
	} else if !validation.Epoch(c.ActiveEpoch) {
		errs.Add(fmt.Errorf("active_epoch %q must be YYYY-MM", c.ActiveEpoch))
	}

	// --- Mode-specific policy ---
	switch c.Mode {
	case ModeProduction:
		validateProduction(c, &errs)
	case ModeDevelopment, ModeTest:
		validateNonProduction(c, &errs)
	}

	// --- Always: epoch list ---
	if len(c.SupportedEpochs) == 0 && c.ActiveEpoch != "" {
		c.SupportedEpochs = []string{c.ActiveEpoch}
	}

	// Ensure supported epochs are valid format and unique
	seen := map[string]struct{}{}
	for _, e := range c.SupportedEpochs {
		if !validation.Epoch(e) {
			errs.Add(fmt.Errorf("supported_epoch %q must be YYYY-MM", e))
		}
		if _, ok := seen[e]; ok {
			errs.Add(fmt.Errorf("duplicate supported_epoch %q", e))
		}
		seen[e] = struct{}{}
	}

	// Ensure active epoch is listed in supported epochs
	if c.ActiveEpoch != "" {
		if !c.IsEpochSupported(c.ActiveEpoch) {
			errs.Add(fmt.Errorf("active_epoch %q is not present in supported_epochs", c.ActiveEpoch))
		}
	}

	return errs.Err()
}
func validateNonProduction(c *Config, errs *ValidationErrors) {
	if c.AuthSecret == "" {
		errs.Add(errors.New("auth_secret is required"))
	}
	if c.RedisAddr == "" && !c.UseMemoryStore {
		errs.Add(errors.New("either redis_addr or use_memory_store must be set"))
	}

	if c.DST == "" {
		c.DST = "BCIS-V1-MESSAGE"
	}
	applyDevDefaults(c)
}

func applyDevDefaults(c *Config) {
	if c.MaxClients <= 0 {
		c.MaxClients = 100000
	}
	if c.RedisExpiration <= 0 {
		c.RedisExpiration = 2592000
	}
}
func validateProduction(c *Config, errs *ValidationErrors) {
	if c.MasterSeedSource == SecretSourceInline {
		errs.Add(errors.New(
			"blindvault_master_seed_hex from config file(YAML) is forbidden in production; " +
				"use BLINDVAULT_MASTER_SEED_HEX or BLINDVAULT_SEED_FILE"))
	}
	if c.UseMemoryStore {
		errs.Add(errors.New("use_memory_store is forbidden in production"))
	}
	if c.AuthSecret == "" {
		errs.Add(errors.New("auth_secret is required in production"))
	} else {
		if len(c.AuthSecret) < 32 {
			errs.Add(fmt.Errorf("auth_secret must be at least 32 characters in production (got %d)",
				len(c.AuthSecret)))
		}
		if c.AuthSecret == "super-secret-token" || c.AuthSecret == "changeme" {
			errs.Add(errors.New("auth_secret is a well-known default value"))
		}
	}
	if c.JWTIssuer == "" {
		errs.Add(errors.New("jwt_issuer is required in production"))
	}
	if c.JWTAudience == "" {
		errs.Add(errors.New("jwt_audience is required in production"))
	}
	if c.UseDemo {
		errs.Add(errors.New("use_demo is forbidden in production"))
	}
	if c.RedisAddr == "" {
		errs.Add(errors.New("redis_addr is required in production"))
	}
	if c.MaxClients <= 0 {
		errs.Add(errors.New("max_clients must be > 0"))
	}
	if c.RedisExpiration <= 0 {
		errs.Add(errors.New("redis_expiration must be > 0"))
	}
	if c.DST == "BCIS-V1-MESSAGE" && os.Getenv("BLINDVAULT_ALLOW_DEFAULT_DST") == "" {
		logger.Warn(context.Background()).Msg("default DST is being used; it is not recommend to use the default")
	}

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
