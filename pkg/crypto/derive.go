package crypto

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"

	blst "github.com/supranational/blst/bindings/go"
)

const (
	// protocolTag is the fixed, immutable protocol identity.
	protocolTag = "BCIS"
	// purpose is the fixed key usage context.
	purpose = "SIGNING_KEY"
	// salt is a fixed, non-secret byte string for domain separation in HKDF.
	salt = "BCIS-V1-SALT"
)

// DeriveSigningKey derives a BLS12-381 signing scalar from the master seed,
// key epoch (lifecycle tag), and credential class (application namespace).
//
// Derivation hierarchy:
//
//	Master Seed
//	    │
//	    └── HKDF-Expand(salt="BCIS-V1-SALT", info="BCIS" || "SIGNING_KEY" || epoch || class)
//	            │
//	            └── 64 bytes → modulo r → BLS12-381 Scalar
//
// This provides:
//   - Protocol isolation (fixed "BCIS" tag)
//   - Purpose isolation (fixed "SIGNING_KEY" tag)
//   - Lifecycle rotation (epoch)
//   - Application namespace isolation (credentialClass)
func DeriveSigningKey(masterSeed []byte, epoch string, credentialClass string) (Scalar, error) {
	if len(masterSeed) == 0 {
		return nil, errors.New("master seed cannot be empty")
	}
	if epoch == "" {
		return nil, errors.New("epoch cannot be empty")
	}
	if credentialClass == "" {
		return nil, errors.New("credential class cannot be empty")
	}

	// Build the info string with strict hierarchical concatenation.
	// Format: "BCIS" + "SIGNING_KEY" + <epoch> + <credentialClass>
	info := protocolTag + purpose + epoch + credentialClass

	// Use HKDF with SHA-256 to derive a 64-byte key from the master seed.
	hkdf_key, err := hkdf.Key(sha256.New, masterSeed, []byte(salt), info, 64)
	if err != nil {
		return nil, err
	}
	// Convert the 64-byte output to a BLS12-381 scalar by reducing modulo r.
	var sk blst.Scalar
	sk.FromBEndian(hkdf_key)

	return &BlstScalar{inner: &sk}, nil
}
