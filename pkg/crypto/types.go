package crypto

type Point interface {
	// Compress returns 48/96‑byte compressed point.
	Compress() []byte
	// IsValid returns true if point is on curve and in correct subgroup.
	IsValid() bool

	Serialize() []byte
}

// PointG1 represents a point on the G1 curve (signature, message).
type PointG1 interface {
	Point
}

// PointG2 represents a point on the G2 curve (public key).
type PointG2 interface {
	Point
}

// Scalar represents a BLS12‑381 scalar (private key, blinding factor).
type Scalar interface {
	PubKey() PointG2
	// Bytes returns the 32‑byte big‑endian representation.
	Bytes() [32]byte
	// IsZero returns true if the scalar is zero.
	IsZero() bool
}

// DLEQProof contains the non‑interactive proof elements.
type DLEQProof struct {
	R1 PointG2 // t * G2
	R2 PointG1 // t * B'
	S  Scalar  // t + c * sk
	C  Scalar  // challenge
}


