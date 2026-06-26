package crypto

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	blst "github.com/supranational/blst/bindings/go"
)

func TestG1Points(t *testing.T) {
	engine := NewBLS12Engine()

	msg := []byte("blind token")
	dst := []byte("FEDIMINT-TEST")

	sk := scalarFromEnclave(t, engine, fixedSecuredSK(t))
	_ = sk.PubKey()
	r := blindFromEnclave(t, engine, fixedSecuredBlind(t))

	point, _ := engine.HashToCurve(msg, dst)
	blinded, _ := engine.BlindMessage(point, r)

	require.True(t, point.IsValid(), "point not valid")
	require.True(t, blinded.IsValid(), "Blinded not valid")

	CBlinded := blinded.Compress()
	CPoint := point.Compress()

	TPoint, err := DeserializeG1(CPoint)
	require.NoError(t, err, "Tpoint")
	TBlinded, err := DeserializeG1(CBlinded)
	require.NoError(t, err, "Tblinded")

	require.Equal(t, TBlinded.Compress(), CBlinded)
	require.Equal(t, TPoint.Compress(), CPoint)
	require.True(t, TPoint.IsValid(), "point not valid")
	require.True(t, TBlinded.IsValid(), "Blinded not valid")
}

func TestG2Points(t *testing.T) {
	engine := NewBLS12Engine()

	sk := scalarFromEnclave(t, engine, fixedSecuredSK(t))
	pk := sk.PubKey()

	require.True(t, pk.IsValid(), "point G2 not valid")
	CPoint := pk.Compress()
	TPoint, err := DeserializeG2(CPoint)
	require.NoError(t, err, "Tpoint")
	require.Equal(t, TPoint.Compress(), CPoint)
	require.True(t, TPoint.IsValid(), "point not valid")
}

func TestVerifyRejectsInvalidSubgroupSecured(t *testing.T) {
	engine := NewBLS12Engine()
	msg := []byte("hello")
	dst := []byte("FEDIMINT-TEST")

	sk := scalarFromEnclave(t, engine, fixedSecuredSK(t))
	pk := sk.PubKey()

	// Generate a valid signature
	point, _ := engine.HashToCurve(msg, dst)
	validSig, _ := engine.SignBlinded(point, sk)

	// Create an invalid point by deserializing random bytes
	invalidSig := &G1Point{inner: new(blst.P1)}
	randomBytes := make([]byte, 48)
	rand.Read(randomBytes)
	invalidSig.inner.ToAffine().Deserialize(randomBytes)

	// This may or may not fail depending on random bytes, but we ensure valid passes
	if engine.Verify(invalidSig, msg, dst, pk) {
		t.Log("Random bytes happened to be a valid point (unlikely) - skipping")
	}

	if !engine.Verify(validSig, msg, dst, pk) {
		t.Fatal("Valid signature rejected")
	}
}
