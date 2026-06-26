package crypto

import (
	"crypto/sha256"
)

// ComputeNullifier generates a unique, deterministic 32-byte hash for a consumed credential.
// It binds the nullifier to the protocol, epoch, credential class, and the actual signature.
// This prevents cross-context replay attacks (e.g., using a signature from epoch "2025-12"
// against epoch "2026-01").
//
// Format: SHA256( "BCIS" || "V1" || epoch || credentialClass || serialize(sig) )
func ComputeNullifier(epoch string, credentialClass string, sig PointG1) []byte {
	h := sha256.New()
	// Write fixed protocol prefix for domain separation
	h.Write([]byte("BCIS-V1"))
	h.Write([]byte(epoch))
	h.Write([]byte(credentialClass))
	// Write the uncompressed serialization of the signature point.
	// Using Serialize() (96 bytes) vs Compress() (48 bytes) adds an extra safety margin
	// against potential compression collisions, though both are deterministic.
	h.Write(sig.Serialize())
	return h.Sum(nil)
}
