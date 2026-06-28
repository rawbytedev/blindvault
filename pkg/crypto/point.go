package crypto

import blst "github.com/supranational/blst/bindings/go"

// G1Point wraps a blst.P1 to implement the PointG1 interface.
type G1Point struct {
	inner *blst.P1
}

// G2Point wraps a blst.P2 to implement the PointG2 interface.
func (p *G1Point) Compress() []byte {
	return p.inner.ToAffine().Compress()
}

// Serialize returns the 48-byte uncompressed representation of the G1 point.
func (p *G1Point) Serialize() []byte {
	return p.inner.Serialize()
}

// IsValid checks if the G1 point is on the curve and in the correct subgroup.
func (p *G1Point) IsValid() bool {
	return p.inner.ToAffine().SigValidate(true)
}

// G2Point wraps a blst.P2 to implement the PointG2 interface.
type G2Point struct {
	inner *blst.P2
}

// Compress returns the 96-byte compressed representation of the G2 point.
func (p *G2Point) Compress() []byte {
	return p.inner.ToAffine().Compress()
}

// Serialize returns the 96-byte uncompressed representation of the G2 point.
func (p *G2Point) Serialize() []byte {
	return p.inner.Serialize()
}

// IsValid checks if the G2 point is on the curve and in the correct subgroup.
func (p *G2Point) IsValid() bool {
	return p.inner.ToAffine().KeyValidate()
}
