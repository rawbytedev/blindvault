package crypto

import (
	"blindvault/pkg/securememory"
	"encoding/hex"
	"testing"
)

// ---------- Fixed Test Keys (wrapped in secure enclaves) ----------
func fixedSecuredSK(t *testing.T) *securememory.Enclave {
	t.Helper()
	skBytes, _ := hex.DecodeString("4a5b6c7d8e9f0123456789abcdef0123456789abcdef0123456789abcdef0123")
	return securememory.NewEnclaveFromBytes(skBytes)
}

func fixedSecuredBlind(t *testing.T) *securememory.Enclave {
	t.Helper()
	rBytes, _ := hex.DecodeString("112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00")
	return securememory.NewEnclaveFromBytes(rBytes)
}

// Helper to open an enclave, convert to Scalar, and auto-close the buffer
func scalarFromEnclave(t *testing.T, engine *BLS12Engine, enc *securememory.Enclave) Scalar {
	t.Helper()
	buff, err := enc.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer buff.Close()
	scalar, err := NewBlstScalarFromBytes(buff.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return scalar
}

// Helper to open an enclave and produce a blinding factor (needs HashTo)
func blindFromEnclave(t *testing.T, engine *BLS12Engine, enc *securememory.Enclave) Scalar {
	t.Helper()
	buff, err := enc.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer buff.Close()
	r := NewBlstScalarWithDomain(buff.Bytes(), []byte("BLINDMX-BLIND-R"))
	if r == nil {
		t.Fatal("failed to derive blinding scalar from enclave")
	}
	return r
}
