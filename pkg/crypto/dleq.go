package crypto

import (
	"errors"

	blst "github.com/supranational/blst/bindings/go"
)

const dleqProofDst = "BCIS-V1-DLEQ-CHALLENGE"

func (e *BLS12Engine) DLEQProve(sk Scalar, blinded PointG1, pk PointG2) (*DLEQProof, error) {
	blstSK := sk.(*BlstScalar).inner
	g1Blinded := blinded.(*G1Point).inner
	g2PK := pk.(*G2Point).inner

	t, err := NewRandomScalar()
	if err != nil {
		return nil, err
	}
	blstT := t.(*BlstScalar).inner

	// 2. R1 = t * G2, R2 = t * B'
	R1 := blst.P2Generator().Mult(blstT)
	R2 := g1Blinded.Mult(blstT)

	// 3. C' = sk * B'
	Cprime := g1Blinded.Mult(blstSK)

	// 4. Challenge c = H(R1 || R2 || PK || B' || C')
	c, err := computeChallenge(R1, R2, g2PK, g1Blinded, Cprime)
	if err != nil {
		return nil, err
	}
	cOriginal := *c
	cCopy := &cOriginal
	c_sk, ok := cCopy.Mul(blstSK)
	if !ok {
		return nil, errors.New("scalar multiplication failed")
	}
	s, ok := blstT.Add(c_sk)
	if !ok {
		return nil, errors.New("scalar addition failed")
	}

	return &DLEQProof{
		R1: &G2Point{inner: R1},
		R2: &G1Point{inner: R2},
		S:  &BlstScalar{inner: s},
		C:  &BlstScalar{inner: c},
	}, nil
}

func (e *BLS12Engine) DLEQVerify(proof *DLEQProof, blinded, sig PointG1, pk PointG2) bool {
	R1 := proof.R1.(*G2Point).inner
	R2 := proof.R2.(*G1Point).inner
	s := proof.S.(*BlstScalar).inner
	c := proof.C.(*BlstScalar).inner

	g1Blinded := blinded.(*G1Point).inner
	g1Sig := sig.(*G1Point).inner
	g2PK := pk.(*G2Point).inner

	cPrime, err := computeChallenge(R1, R2, g2PK, g1Blinded, g1Sig)
	if err != nil || !c.Equals(cPrime) {
		return false
	}

	left1 := blst.P2Generator().Mult(s)

	pkCopy := new(blst.P2)
	*pkCopy = *g2PK
	tmp := pkCopy.Mult(c)

	r1Copy := new(blst.P2)
	*r1Copy = *R1
	right1 := r1Copy.Add(tmp)

	if !left1.Equals(right1) {
		return false
	}

	left2 := g1Blinded.Mult(s)

	sigCopy := new(blst.P1)
	*sigCopy = *g1Sig
	tmp1 := sigCopy.Mult(c)

	r2Copy := new(blst.P1)
	*r2Copy = *R2
	right2 := r2Copy.Add(tmp1)

	return left2.Equals(right2)
}
func computeChallenge(R1 *blst.P2, R2 *blst.P1, PK *blst.P2, Bprime, Cprime *blst.P1) (*blst.Scalar, error) {
	r1Comp := R1.ToAffine().Compress()
	if r1Comp == nil {
		return nil, errors.New("R1 compress returned nil")
	}
	r2Comp := R2.ToAffine().Compress()
	if r2Comp == nil {
		return nil, errors.New("R2 compress returned nil")
	}
	pkComp := PK.ToAffine().Compress()
	if pkComp == nil {
		return nil, errors.New("PK compress returned nil")
	}
	bComp := Bprime.ToAffine().Compress()
	if bComp == nil {
		return nil, errors.New("Bprime compress returned nil")
	}
	cComp := Cprime.ToAffine().Compress()
	if cComp == nil {
		return nil, errors.New("Cprime compress returned nil")
	}

	data := make([]byte, 0, 48+96+96+96+48+48)
	data = append(data, r1Comp...)
	data = append(data, r2Comp...)
	data = append(data, pkComp...)
	data = append(data, bComp...)
	data = append(data, cComp...)

	var c blst.Scalar
	if !c.HashTo(data, []byte(dleqProofDst)) {
		return nil, errors.New("challenge hash-to-scalar failed")
	}
	return &c, nil
}
