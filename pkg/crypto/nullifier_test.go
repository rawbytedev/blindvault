package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestComputeNullifier(t *testing.T) {
	engine := NewBLS12Engine()
	skBytes, _ := hex.DecodeString("4a5b6c7d8e9f0123456789abcdef0123456789abcdef0123456789abcdef0123")
	sk, _ := NewBlstScalarFromBytes(skBytes)
	msg := []byte("test")
	dst := []byte("BCIS-TEST")
	point, _ := engine.HashToCurve(msg, dst)
	sig, _ := engine.SignBlinded(point, sk)

	nullifier1 := ComputeNullifier("2026-01", "test_class", sig)
	require.Len(t, nullifier1, 32)

	// Same inputs should produce same nullifier
	nullifier2 := ComputeNullifier("2026-01", "test_class", sig)
	require.Equal(t, nullifier1, nullifier2)

	// Different epoch changes nullifier
	nullifier3 := ComputeNullifier("2025-12", "test_class", sig)
	require.NotEqual(t, nullifier1, nullifier3)

	// Different class changes nullifier
	nullifier4 := ComputeNullifier("2026-01", "other_class", sig)
	require.NotEqual(t, nullifier1, nullifier4)

	// test with a different signature from another key
	sk2, _ := NewRandomScalar()
	sig3, _ := engine.SignBlinded(point, sk2)
	nullifier5 := ComputeNullifier("2026-01", "test_class", sig3)
	require.NotEqual(t, nullifier1, nullifier5)
}
