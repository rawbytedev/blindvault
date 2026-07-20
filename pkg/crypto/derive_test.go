package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeriveSigningKey(t *testing.T) {
	masterSeed, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	// Test valid derivation
	sk, err := DeriveSigningKey(masterSeed, "2026-01", "tier_gold")
	require.NoError(t, err)
	require.NotNil(t, sk)
	require.False(t, sk.IsZero())

	// Test deterministic output
	sk2, err := DeriveSigningKey(masterSeed, "2026-01", "tier_gold")
	require.NoError(t, err)
	require.Equal(t, sk.Bytes(), sk2.Bytes())

	// Different class gives different key
	sk3, err := DeriveSigningKey(masterSeed, "2026-01", "faucet")
	require.NoError(t, err)
	require.NotEqual(t, sk.Bytes(), sk3.Bytes())

	// Different epoch
	sk4, err := DeriveSigningKey(masterSeed, "2025-12", "tier_gold")
	require.NoError(t, err)
	require.NotEqual(t, sk.Bytes(), sk4.Bytes())

	// Test error cases
	_, err = DeriveSigningKey(nil, "2026-01", "test")
	require.Error(t, err)
	require.Contains(t, err.Error(), "master seed cannot be empty")

	_, err = DeriveSigningKey(masterSeed, "", "test")
	require.Error(t, err)
	require.Contains(t, err.Error(), "epoch cannot be empty")

	_, err = DeriveSigningKey(masterSeed, "2026-01", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "credential class cannot be empty")
}
