package crypto

import blst "github.com/supranational/blst/bindings/go"

type G1Point struct {
	inner *blst.P1
}

func (p *G1Point) Compress() []byte {
	return p.inner.ToAffine().Compress()
}

func (p *G1Point) Serialize() []byte {
	return p.inner.Serialize()
}

func (p *G1Point) IsValid() bool {
	return p.inner.ToAffine().SigValidate(true)
}

type G2Point struct {
	inner *blst.P2
}

func (p *G2Point) Compress() []byte {
	return p.inner.ToAffine().Compress()
}

func (p *G2Point) Serialize() []byte {
	return p.inner.Serialize()
}

func (p *G2Point) IsValid() bool {
	return p.inner.ToAffine().KeyValidate()
}
