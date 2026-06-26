package config

import (
	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	MasterSeed      []byte // loaded from vault
	ActiveEpoch     string
	SupportedEpochs []string
	DST             []byte
	BadgerDBPath    string
}

// Load parses environment variables and returns a Config.
// It also validates required fields.
func Load() (*Config, error) {
	var cfg Config
	err := envconfig.Process("", &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}
