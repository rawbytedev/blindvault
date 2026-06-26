package crypto

import (
	"errors"

	blst "github.com/supranational/blst/bindings/go"
)

// DeserializeG1 validates and returns a G1 point from compressed bytes.
func DeserializeG1(data []byte) (PointG1, error) {
	pt := new(blst.P1Affine)
	p := new(blst.P1)
	if pt.Uncompress(data) == nil {
		return nil, errors.New("invalid G1 point: deserialization failed")
	}
	p.FromAffine(pt)
	// Enable subgroup check for security (true)
	if !p.ToAffine().InG1() {
		return nil, errors.New("G1 point not in correct subgroup")
	}
	return &G1Point{inner: p}, nil
}

// DeserializeG2 validates and returns a G2 point from compressed bytes.
func DeserializeG2(data []byte) (PointG2, error) {
	pt := new(blst.P2Affine)
	p := new(blst.P2)
	if pt.Uncompress(data) == nil {
		return nil, errors.New("invalid G2 point: deserialization failed")
	}
	//
	p.FromAffine(pt)
	// Enable subgroup check for security (true)
	if !p.ToAffine().InG2() {
		return nil, errors.New("G2 point not in correct subgroup")
	}
	return &G2Point{inner: p}, nil
}
