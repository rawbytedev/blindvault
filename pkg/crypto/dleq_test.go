package crypto

import "testing"

func TestTamperedDLEQFailsSecured(t *testing.T) {
	engine := NewBLS12Engine()

	msg := []byte("hello")
	dst := []byte("FEDIMINT-TEST")

	sk := scalarFromEnclave(t, engine, fixedSecuredSK(t))
	pk := sk.PubKey()
	r := blindFromEnclave(t, engine, fixedSecuredBlind(t))

	point, _ := engine.HashToCurve(msg, dst)
	blinded, _ := engine.BlindMessage(point, r)
	blindSig, _ := engine.SignBlinded(blinded, sk)

	proof, _ := engine.DLEQProve(sk, blinded, pk)

	// Replace challenge with a different blinding factor (tampering)
	r2 := blindFromEnclave(t, engine, fixedSecuredBlind(t))
	proof.C = r2

	if engine.DLEQVerify(proof, blinded, blindSig, pk) {
		t.Fatal("tampered proof should fail")
	}
}
