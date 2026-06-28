package crypto

type Engine interface {
	// HashToCurve hashes the input data to a point on the G1 curve using the specified domain separation tag (dst).
	HashToCurve(data []byte, dst []byte) (PointG1, error)
	// BlindMessage blinds a message point using a blinding factor.
	BlindMessage(msg PointG1, r Scalar) (PointG1, error)
	// SignBlinded signs a blinded message point using the private key.
	SignBlinded(blinded PointG1, sk Scalar) (PointG1, error)
	// UnblindSignature unblinds a signature point using the blinding factor.
	UnblindSignature(sig PointG1, r Scalar) (PointG1, error)
	// Verify verifies that the signature is valid for the given message and public key.
	Verify(sig PointG1, msg []byte, dst []byte, pk PointG2) bool
	// VerifyPoint verifies that the signature is valid for the given message point and public key.
	VerifyPoint(sig PointG1, msg PointG1, pk PointG2) bool
	// DLEQVerify verifies a non-interactive proof of knowledge of the discrete logarithm equality.
	DLEQVerify(proof *DLEQProof, blinded PointG1, sig PointG1, pk PointG2) bool
	// DLEQProve generates a non-interactive proof of knowledge of the discrete logarithm equality.
	DLEQProve(sk Scalar, blinded PointG1, sig PointG2) (*DLEQProof, error)
}

// Point represents a point on the elliptic curve.
type Point interface {
	// Compress returns 48/96‑byte compressed point.
	Compress() []byte
	// IsValid returns true if point is on curve and in correct subgroup.
	IsValid() bool
	// Serialize returns the uncompressed representation of the point.
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
