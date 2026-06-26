package crypto

import (
	"bytes"
	"testing"
)

func TestSimpleSecuredVerify(t *testing.T) {
	engine := NewBLS12Engine()

	msg := []byte("hello")
	dst := []byte("FEDIMINT-TEST")

	sk := scalarFromEnclave(t, engine, fixedSecuredSK(t))
	pk := sk.PubKey()

	point, _ := engine.HashToCurve(msg, dst)
	sig, _ := engine.SignBlinded(point, sk)

	if !engine.Verify(sig, msg, dst, pk) {
		t.Fatal("signature invalid")
	}
}

func TestBlindSignatureFlowSecured(t *testing.T) {
	engine := NewBLS12Engine()

	msg := []byte("blind token")
	dst := []byte("FEDIMINT-TEST")

	sk := scalarFromEnclave(t, engine, fixedSecuredSK(t))
	pk := sk.PubKey()
	r := blindFromEnclave(t, engine, fixedSecuredBlind(t))

	point, _ := engine.HashToCurve(msg, dst)
	blinded, _ := engine.BlindMessage(point, r)

	blindSig, _ := engine.SignBlinded(blinded, sk)

	proof, err := engine.DLEQProve(sk, blinded, pk)
	if err != nil {
		t.Fatal(err)
	}
	if !engine.DLEQVerify(proof, blinded, blindSig, pk) {
		t.Fatal("DLEQ invalid")
	}

	finalSig, _ := engine.UnblindSignature(blindSig, r)

	if !engine.Verify(finalSig, msg, dst, pk) {
		t.Fatal("final signature invalid")
	}
}

func TestWrongMessageFailsSecured(t *testing.T) {
	engine := NewBLS12Engine()

	msg := []byte("hello")
	wrong := []byte("tampered")
	dst := []byte("FEDIMINT-TEST")

	sk := scalarFromEnclave(t, engine, fixedSecuredSK(t))
	pk := sk.PubKey()

	point, _ := engine.HashToCurve(msg, dst)
	sig, _ := engine.SignBlinded(point, sk)

	if engine.Verify(sig, wrong, dst, pk) {
		t.Fatal("verification should fail")
	}
}

func TestWrongDSTFailsSecured(t *testing.T) {
	engine := NewBLS12Engine()

	msg := []byte("hello")

	sk := scalarFromEnclave(t, engine, fixedSecuredSK(t))
	pk := sk.PubKey()

	point, _ := engine.HashToCurve(msg, []byte("DST1"))
	sig, _ := engine.SignBlinded(point, sk)

	if engine.Verify(sig, msg, []byte("DST2"), pk) {
		t.Fatal("verification should fail")
	}
}

func TestUnblindSignatureDoesNotMutateScalarSecured(t *testing.T) {
	engine := NewBLS12Engine()
	msg := []byte("test")
	dst := []byte("FEDIMINT-TEST")

	sk := scalarFromEnclave(t, engine, fixedSecuredSK(t))
	rEnc := fixedSecuredBlind(t)
	r := blindFromEnclave(t, engine, rEnc)

	// Create a copy of r to compare later (by re-opening the enclave)
	rOrigBuff, err := rEnc.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer rOrigBuff.Close()
	rOrigBytes := rOrigBuff.Bytes()

	point, _ := engine.HashToCurve(msg, dst)
	blinded, _ := engine.BlindMessage(point, r)
	blindSig, _ := engine.SignBlinded(blinded, sk)

	_, err = engine.UnblindSignature(blindSig, r)
	if err != nil {
		t.Fatal(err)
	}
	// Re-open the enclave to check if the underlying bytes changed (they should not)
	newBuff, err := rEnc.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer newBuff.Close()
	newBytes := newBuff.Bytes()

	if !bytes.Equal(newBytes, rOrigBytes) {
		t.Fatal("UnblindSignature mutated the original enclave data")
	}
}
