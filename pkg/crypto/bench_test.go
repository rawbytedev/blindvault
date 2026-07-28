package crypto

import (
    "testing"
)

// BenchmarkHashToCurve measures G1 hashing performance.
func BenchmarkHashToCurve(b *testing.B) {
    engine := NewBLS12Engine()
    msg := []byte("benchmark message")
    dst := []byte("BCIS-V1-MESSAGE")

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, _ = engine.HashToCurve(msg, dst)
    }
}

// BenchmarkBlindMessage measures blind message generation.
func BenchmarkBlindMessage(b *testing.B) {
    engine := NewBLS12Engine()
    msg := []byte("benchmark message")
    dst := []byte("BCIS-V1-MESSAGE")
    point, _ := engine.HashToCurve(msg, dst)
    r, _ := NewRandomScalar()

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, _ = engine.BlindMessage(point, r)
    }
}

// BenchmarkSignBlinded measures blind signing (server-side).
func BenchmarkSignBlinded(b *testing.B) {
    engine := NewBLS12Engine()
    msg := []byte("benchmark message")
    dst := []byte("BCIS-V1-MESSAGE")
    point, _ := engine.HashToCurve(msg, dst)
    r, _ := NewRandomScalar()
    blinded, _ := engine.BlindMessage(point, r)
    sk, _ := NewRandomScalar()

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, _ = engine.SignBlinded(blinded, sk)
    }
}

// BenchmarkUnblindSignature measures client-side unblinding.
func BenchmarkUnblindSignature(b *testing.B) {
    engine := NewBLS12Engine()
    msg := []byte("benchmark message")
    dst := []byte("BCIS-V1-MESSAGE")
    point, _ := engine.HashToCurve(msg, dst)
    r, _ := NewRandomScalar()
    blinded, _ := engine.BlindMessage(point, r)
    sk, _ := NewRandomScalar()
    blindSig, _ := engine.SignBlinded(blinded, sk)

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, _ = engine.UnblindSignature(blindSig, r)
    }
}

// BenchmarkDLEQProve measures server-side proof generation.
func BenchmarkDLEQProve(b *testing.B) {
    engine := NewBLS12Engine()
    msg := []byte("benchmark message")
    dst := []byte("BCIS-V1-MESSAGE")
    point, _ := engine.HashToCurve(msg, dst)
    r, _ := NewRandomScalar()
    blinded, _ := engine.BlindMessage(point, r)
    sk, _ := NewRandomScalar()
    pk := sk.PubKey()

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, _ = engine.DLEQProve(sk, blinded, pk)
    }
}

// BenchmarkDLEQVerify measures client-side proof verification.
func BenchmarkDLEQVerify(b *testing.B) {
    engine := NewBLS12Engine()
    msg := []byte("benchmark message")
    dst := []byte("BCIS-V1-MESSAGE")
    point, _ := engine.HashToCurve(msg, dst)
    r, _ := NewRandomScalar()
    blinded, _ := engine.BlindMessage(point, r)
    sk, _ := NewRandomScalar()
    pk := sk.PubKey()
    blindSig, _ := engine.SignBlinded(blinded, sk)
    proof, _ := engine.DLEQProve(sk, blinded, pk)

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _ = engine.DLEQVerify(proof, blinded, blindSig, pk)
    }
}

// BenchmarkFullFlow measures the complete client+server flow (excluding network).
func BenchmarkFullFlow(b *testing.B) {
    engine := NewBLS12Engine()
    msg := []byte("benchmark message")
    dst := []byte("BCIS-V1-MESSAGE")
    sk, _ := NewRandomScalar()
    pk := sk.PubKey()

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        // 1. Client: hash + blind
        point, _ := engine.HashToCurve(msg, dst)
        r, _ := NewRandomScalar()
        blinded, _ := engine.BlindMessage(point, r)

        // 2. Server: sign + prove
        blindSig, _ := engine.SignBlinded(blinded, sk)
        proof, _ := engine.DLEQProve(sk, blinded, pk)

        // 3. Client: verify + unblind
        _ = engine.DLEQVerify(proof, blinded, blindSig, pk)
        _, _ = engine.UnblindSignature(blindSig, r)
    }
}
