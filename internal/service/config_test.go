package service

import (
	"testing"

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
				ActiveEpoch: "2026-01",
				AuthSecret:  "secret",
				RedisAddr:   "localhost:6379",
			},
			wantErr: true,
			errMsg:  "master_seed_hex is required",
		},
		{
			name: "invalid master seed length",
			cfg: Config{
				MasterSeedHex: "1234",
				ActiveEpoch:   "2026-01",
				AuthSecret:    "secret",
				RedisAddr:     "localhost:6379",
			},
			wantErr: true,
			errMsg:  "must be 64 hex characters",
		},
		{
			name: "missing active epoch",
			cfg: Config{
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
				MasterSeedHex:  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
				ActiveEpoch:    "2026-01",
				AuthSecret:     "secret",
				UseMemoryStore: false,
			},
			wantErr: true,
			errMsg:  "redis_addr must be provided",
		},
		{
			name: "memory store ok without redis",
			cfg: Config{
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
			err := tt.cfg.Validate()
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					require.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestConfig_MasterSeed(t *testing.T) {
	cfg := &Config{MasterSeedHex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"}
	seed, err := cfg.MasterSeed()
	require.NoError(t, err)
	require.Len(t, seed, 32)
}

func TestConfig_DSTBytes(t *testing.T) {
	cfg := &Config{DST: "BCIS-TEST"}
	require.Equal(t, []byte("BCIS-TEST"), cfg.DSTBytes())
}

func TestConfig_IsEpochSupported(t *testing.T) {
	cfg := &Config{SupportedEpochs: []string{"2026-01", "2026-02"}}
	require.True(t, cfg.IsEpochSupported("2026-01"))
	require.False(t, cfg.IsEpochSupported("2025-12"))
}
