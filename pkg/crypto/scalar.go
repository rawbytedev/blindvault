package crypto

import (
	"crypto/rand"
	"errors"
	"math/big"

	blst "github.com/supranational/blst/bindings/go"
)

const randomScalarDST = "BCIS-V1-INTERNAL-RANDOM"

// BlstScalar wraps a blst.Scalar to implement the Scalar interface.
type BlstScalar struct {
	inner *blst.Scalar
}

// NewBlstScalar creates a new BlstScalar from a blst.Scalar.
func NewBlstScalar(inner *blst.Scalar) Scalar {
	return &BlstScalar{inner: inner}
}

// Bytes returns the 32-byte big-endian representation of the scalar.
func (s *BlstScalar) Bytes() [32]byte {
	var b [32]byte
	copy(b[:], s.inner.Serialize()) // Already big‑endian
	return b
}

// IsZero checks if the scalar is zero.
func (s *BlstScalar) IsZero() bool {
	for _, v := range s.inner.Serialize() {
		if v != 0 {
			return false
		}
	}
	return true
}

// PubKey derives the public key (G2 point) from the scalar (private key).
func (s *BlstScalar) PubKey() PointG2 {
	return &G2Point{
		inner: blst.P2Generator().Mult(s.inner),
	}
}

// NewBlstScalarFromBytes creates a new BlstScalar from a 32-byte big-endian representation.
func NewBlstScalarFromBytes(b []byte) (Scalar, error) {
	if len(b) != 32 {
		return nil, errors.New("scalar must be 32 bytes")
	}
	// Interpret as big-endian integer and ensure it's in [0, r-1]
	v := new(big.Int).SetBytes(b)
	// Order r for BLS12-381 scalar field (Fr)
	// r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
	rHex := "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
	r := new(big.Int)
	r.SetString(rHex, 16)
	if v.Cmp(r) >= 0 {
		return nil, errors.New("scalar is out of range")
	}
	var s blst.Scalar
	s.FromBEndian(b)
	return &BlstScalar{inner: &s}, nil
}

func NewBlstScalarWithDomain(b []byte, domain []byte) Scalar {
	var sk blst.Scalar
	if !sk.HashTo(b, domain) {
		return nil
	}
	return &BlstScalar{inner: &sk}
}

// NewRandomScalar generates a cryptographically secure random scalar
func NewRandomScalar() (Scalar, error) {
	seed := make([]byte, 48)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	var s blst.Scalar
	if !s.HashTo(seed, []byte(randomScalarDST)) {
		return nil, errors.New("random scalar generation failed")
	}
	return &BlstScalar{inner: &s}, nil
}
