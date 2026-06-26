package crypto

import (
	"errors"

	blst "github.com/supranational/blst/bindings/go"
)

type BLS12Engine struct {
}

func NewBLS12Engine() *BLS12Engine {
	return &BLS12Engine{}
}

func (e *BLS12Engine) HashToCurve(data []byte, dst []byte) (PointG1, error) {
	if dst == nil {
		return nil, errors.New("dst required")
	}
	p := blst.HashToG1(data, dst, nil)
	return &G1Point{inner: p}, nil
}

func (e *BLS12Engine) BlindMessage(msg PointG1, r Scalar) (PointG1, error) {
	p := new(blst.P1)
	*p = *msg.(*G1Point).inner
	blinded := p.Mult(r.(*BlstScalar).inner)
	return &G1Point{inner: blinded}, nil
}

func (e *BLS12Engine) SignBlinded(blinded PointG1, sk Scalar) (PointG1, error) {
	p := new(blst.P1)
	*p = *blinded.(*G1Point).inner
	sig := p.Mult(sk.(*BlstScalar).inner)
	return &G1Point{inner: sig}, nil
}

func (e *BLS12Engine) UnblindSignature(sig PointG1, r Scalar) (PointG1, error) {
	// Clone the scalar to avoid mutating the caller's value
	rCopy := new(blst.Scalar)
	*rCopy = *r.(*BlstScalar).inner
	inv := rCopy.Inverse()

	p := new(blst.P1)
	*p = *sig.(*G1Point).inner

	return &G1Point{inner: p.Mult(inv)}, nil
}

// Verify checks e(σ, G2) == e(M, PK)
func (e *BLS12Engine) Verify(sig PointG1, msg []byte, dst []byte, pk PointG2) bool {
	sigAff := sig.(*G1Point).inner.ToAffine()
	pkAff := pk.(*G2Point).inner.ToAffine()
	err := sigAff.Verify(
		true,
		pkAff,
		true,
		msg,
		[]byte(dst),
	)

	return err
}

func (e *BLS12Engine) VerifyPoint(sig PointG1, msgPoint PointG1, pk PointG2) bool {
	sigAff := sig.(*G1Point).inner.ToAffine()
	msgAff := msgPoint.(*G1Point).inner.ToAffine()
	pkAff := pk.(*G2Point).inner.ToAffine()
	g2Aff := blst.P2Generator().ToAffine()
	// gt1 = e(G2, sig)
	gt1 := blst.Fp12MillerLoop(g2Aff, sigAff)
	// gt2 = e(pk, msgPoint)
	gt2 := blst.Fp12MillerLoop(pkAff, msgAff)
	return blst.Fp12FinalVerify(gt1, gt2)
}
