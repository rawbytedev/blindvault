package service

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/rawbytedev/blindvault/pkg/securememory"
	"github.com/stretchr/testify/require"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid config",
			cfg: Config{
				Mode:            "development",
				MasterSeedHex:   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
				ActiveEpoch:     "2026-01",
				SupportedEpochs: []string{"2026-01"},
				AuthSecret:      "secret",
				RedisAddr:       "localhost:6379",
			},
			wantErr: false,
		},
		{
			name: "missing master seed",
			cfg: Config{
				Mode:        "development",
				ActiveEpoch: "2026-01",
				AuthSecret:  "secret",
				RedisAddr:   "localhost:6379",
			},
			wantErr: true,
			errMsg:  "no master seed source configured",
		},
		{
			name: "invalid master seed length",
			cfg: Config{
				Mode:          "development",
				MasterSeedHex: "1234",
				ActiveEpoch:   "2026-01",
				AuthSecret:    "secret",
				RedisAddr:     "localhost:6379",
			},
			wantErr: true,
			errMsg:  "master seed must decode to 32 bytes",
		},
		{
			name: "missing active epoch",
			cfg: Config{
				Mode:          "development",
				MasterSeedHex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
				AuthSecret:    "secret",
				RedisAddr:     "localhost:6379",
			},
			wantErr: true,
			errMsg:  "active_epoch is required",
		},
		{
			name: "missing auth secret",
			cfg: Config{
				Mode:          "development",
				MasterSeedHex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
				ActiveEpoch:   "2026-01",
				RedisAddr:     "localhost:6379",
			},
			wantErr: true,
			errMsg:  "auth_secret is required",
		},
		{
			name: "missing redis when not memory store",
			cfg: Config{
				Mode:           "development",
				MasterSeedHex:  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
				ActiveEpoch:    "2026-01",
				AuthSecret:     "secret",
				UseMemoryStore: false,
			},
			wantErr: true,
			errMsg:  "redis_addr or use_memory_store must be set",
		},
		{
			name: "memory store ok without redis",
			cfg: Config{
				Mode:           "development",
				MasterSeedHex:  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
				ActiveEpoch:    "2026-01",
				AuthSecret:     "secret",
				UseMemoryStore: true,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.LoadMasterSeed()
			if err != nil {
				require.Contains(t, err.Error(), tt.errMsg)
			} else {
				err = tt.cfg.Validate()
				if tt.wantErr {
					require.Error(t, err)
					if tt.errMsg != "" {
						require.Contains(t, err.Error(), tt.errMsg)
					}
				} else {
					require.NoError(t, err)
				}
			}
		})
	}
}

func TestConfig_MasterSeed(t *testing.T) {
	cfg := &Config{MasterSeedHex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"}
	seed, err := cfg.MasterSeed()
	require.NoError(t, err)
	buf, err := seed.Open()
	require.NoError(t, err)
	defer buf.Close()
	require.Len(t, buf.Bytes(), 32)
}

func TestConfig_DSTBytes(t *testing.T) {
	cfg := &Config{DST: "BCIS-TEST"}
	require.Equal(t, []byte("BCIS-TEST"), cfg.DSTBytes())
}

func TestConfig_LoadMasterSeed(t *testing.T) {
	seedHex := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	t.Setenv("BLINDVAULT_MASTER_SEED_HEX", seedHex)
	cfg := &Config{}
	require.NoError(t, cfg.LoadMasterSeed())
	seedEnclave, err := cfg.MasterSeed()
	require.NoError(t, err)
	buf, err := seedEnclave.Open()
	require.NoError(t, err)
	defer buf.Close()
	require.Equal(t, seedHex, hex.EncodeToString(buf.Bytes()))
}

func TestConfig_IsEpochSupported(t *testing.T) {
	cfg := &Config{SupportedEpochs: []string{"2026-01", "2026-02"}}
	require.True(t, cfg.IsEpochSupported("2026-01"))
	require.False(t, cfg.IsEpochSupported("2025-12"))
}

func TestConfig_ProductionRejectsInlineSeed(t *testing.T) {
	cfg := &Config{
		Mode:              ModeProduction,
		MasterSeedSource:  SecretSourceInline,
		AuthSecret:        strings.Repeat("a", 64),
		RedisAddr:         "localhost:6379",
		ActiveEpoch:       "2026-01",
		JWTIssuer:         "blindvault",
		JWTAudience:       "api",
		DST:               "BCIS-V1-MESSAGE",
		MasterSeedEnclave: securememory.NewEnclaveFromBytes(make([]byte, 32)),
	}
	err := cfg.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "forbidden in production")
}

func TestConfig_ProductionRejectsMemoryStore(t *testing.T) {
	cfg := &Config{
		Mode:              ModeProduction,
		MasterSeedSource:  SecretSourceEnv,
		AuthSecret:        strings.Repeat("a", 64),
		UseMemoryStore:    true,
		ActiveEpoch:       "2026-01",
		JWTIssuer:         "blindvault",
		JWTAudience:       "api",
		DST:               "BCIS-V1-MESSAGE",
		MasterSeedEnclave: securememory.NewEnclaveFromBytes(make([]byte, 32)),
	}
	err := cfg.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "use_memory_store is forbidden")
}

func TestConfig_ProductionAccumulatesErrors(t *testing.T) {
	cfg := &Config{
		Mode:              ModeProduction,
		MasterSeedSource:  SecretSourceInline,
		AuthSecret:        "short",
		UseMemoryStore:    true,
		ActiveEpoch:       "2026-01",
		MasterSeedEnclave: securememory.NewEnclaveFromBytes(make([]byte, 32)),
	}
	err := cfg.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "auth_secret must be at least 32")
	require.Contains(t, err.Error(), "redis_addr is required")
	require.Contains(t, err.Error(), "jwt_issuer is required")
	require.Contains(t, err.Error(), "jwt_audience is required")
	require.Contains(t, err.Error(), "blindvault_master_seed_hex from config file(YAML) is forbidden")
}
