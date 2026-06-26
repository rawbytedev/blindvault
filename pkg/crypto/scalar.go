package crypto

import (
	"crypto/rand"
	"errors"

	blst "github.com/supranational/blst/bindings/go"
)

const randomScalarDST = "BCIS-V1-INTERNAL-RANDOM"

type BlstScalar struct {
	inner *blst.Scalar
}

func NewBlstScalar(inner *blst.Scalar) *BlstScalar {
	return &BlstScalar{inner: inner}
}

func (s *BlstScalar) Bytes() [32]byte {
	var b [32]byte
	copy(b[:], s.inner.Serialize()) // Already big‑endian
	return b
}

func (s *BlstScalar) IsZero() bool {
	for _, v := range s.inner.Serialize() {
		if v != 0 {
			return false
		}
	}
	return true
}

func (s *BlstScalar) PubKey() PointG2 {
	return &G2Point{
		inner: blst.P2Generator().Mult(s.inner),
	}
}

func NewBlstScalarFromBytes(b []byte) (*BlstScalar, error) {
	if len(b) != 32 {
		return nil, errors.New("scalar must be 32 bytes")
	}
	var s blst.Scalar
	s.FromBEndian(b)
	return &BlstScalar{inner: &s}, nil
}

func NewBlstScalarWithDomain(b []byte, domain []byte) *BlstScalar {
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
