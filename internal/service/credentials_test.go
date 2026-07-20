package service

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/rawbytedev/blindvault/internal/storage"
	"github.com/rawbytedev/blindvault/pkg/crypto"
	"github.com/stretchr/testify/require"
)

func TestCredentialService_Consume_Revoked(t *testing.T) {
	cfg := &Config{
		MasterSeedHex:   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		ActiveEpoch:     "2026-01",
		SupportedEpochs: []string{"2026-01"},
		DST:             "BCIS-TEST",
		UseMemoryStore:  true,
	}

	nullifierStore := storage.NewInMemoryNullifierStore()
	revocationStore := storage.NewInMemoryRevocationStore()
	svc := NewCredentialService(cfg, nullifierStore, revocationStore)

	// Issue a valid credential
	engine := crypto.NewBLS12Engine()
	msg := []byte("test message")
	dst := []byte("BCIS-TEST")
	point, _ := engine.HashToCurve(msg, dst)
	r, _ := crypto.NewRandomScalar()
	blinded, _ := engine.BlindMessage(point, r)
	Issuance, err := svc.Issue(context.Background(), hex.EncodeToString(blinded.Compress()), "test")
	require.NoError(t, err, "Issuance Failed")
	blindhex, err := hex.DecodeString(Issuance.BlindSignature)
	require.NoError(t, err)
	blindSid, err := crypto.DeserializeG1(blindhex)
	require.NoError(t, err, "Deserialization failed for sig")
	unblinded, _ := engine.UnblindSignature(blindSid, r)

	sigHex := hex.EncodeToString(unblinded.Compress())
	witnessHex := hex.EncodeToString(point.Compress())

	// First consume should succeed
	result, err := svc.Consume(context.Background(), sigHex, witnessHex, "test", "2026-01")
	require.NoError(t, err)
	require.True(t, result.Valid)

	// Revoke the class
	err = revocationStore.RevokeClass("test", "2026-01", "test revocation", "admin", nil)
	require.NoError(t, err)

	// Second consume should fail due to revocation
	result, err = svc.Consume(context.Background(), sigHex, witnessHex, "test", "2026-01")
	require.NoError(t, err)
	require.False(t, result.Valid)
	require.Contains(t, result.Error, "revoked")
}

func TestCredentialService_Close(t *testing.T) {
	cfg := &Config{
		MasterSeedHex:   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		ActiveEpoch:     "2026-01",
		SupportedEpochs: []string{"2026-01"},
		DST:             "BCIS-TEST",
		UseMemoryStore:  true,
	}
	nullifierStore := storage.NewInMemoryNullifierStore()
	revocationStore := storage.NewInMemoryRevocationStore()
	svc := NewCredentialService(cfg, nullifierStore, revocationStore)

	err := svc.Close()
	require.NoError(t, err)
}
