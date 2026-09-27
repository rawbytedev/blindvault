# Cryptographic Specification

## Overview

This document describes BlindVault's cryptographic construction for blind credential issuance and consumption.

## Key Derivation Hierarchy

The server derives epoch- and class-specific signing keys from a single master seed using HKDF-SHA256.

- Master seed: 32-byte hex string.
- Epoch: lifecycle tag, e.g. `2026-01`.
- Credential class: application namespace, e.g. `tier_gold`.

### Derivation formula
"\x00" : is used as a separator

```
DeriveSigningKey(master_seed, epoch, credential_class):
  info = "BCIS" +"\x00"+ "SIGNING_KEY"+"\x00"+ epoch +"\x00"+ credential_class
  prk = HKDF-Extract(salt="BCIS-V1-SALT", IKM=master_seed)
  okm = HKDF-Expand(prk, info, 64)
  sk = blst.Scalar.HashTo(okm, []byte("BCIS-V1-SCALAR"))
```

This produces a BLS12-381 scalar used for blind signing.

## Blinding and Issuance

### Client-side issuance flow

1. Hash message into G1: `B' = HashToCurve(message, DST)`.
2. Pick blinding scalar `r <- RandomScalar()`.
3. Compute `B'' = r * B'`.
4. Send `B''` as `blinded_message` to the server.

### Server signing

1. Derive signing key `sk` for epoch/class.
2. Compute blind signature `σ' = sk * B''`.
3. Compute DLEQ proof for `(B'', σ')`.
4. Return `blind_signature`, `public_key`, `key_epoch`, and `proof`.

## DLEQ Proof

The server proves the relationship between the blinded message and the public key without revealing the signing scalar.

### Proof generation

- Choose random scalar `t`.
- `R1 = t * G2`.
- `R2 = t * B''`.
- `C' = sk * B''`.
- `c = Hash(R1 || R2 || PK || B'' || C')` using `DST = "BCIS-V1-DLEQ-CHALLENGE"`.
- `s = t + c * sk`.

Proof elements returned:

- `r1`: compressed G2 point.
- `r2`: compressed G1 point.
- `s`: scalar.
- `c`: scalar.

### Proof verification

Check:

- Recompute `c' = Hash(R1 || R2 || PK || B'' || σ')`.
- Verify `s * G2 == R1 + c * PK`.
- Verify `s * B'' == R2 + c * σ'`.

## Credential Consumption and Nullifiers

### Verification

The client sends:

- `unblinded_signature`: compressed G1 signature.
- `witness`: compressed G1 point `B' = HashToCurve(message, DST)`.
- `credential_class`.
- `key_epoch`.

The server derives `pk` for the same epoch/class and checks:

- `e(σ, G2) == e(B', PK)`.

### Nullifier construction

The nullifier is computed as:
"\x00" : is used as separator
"\x01": the trailing byte is the version

```
nullifier = SHA256("BCIS-V1" + "\x00" + epoch + "\x00" + credential_class + "\x00" + Serialize(σ) + "\x01")
```

This binds redemption to the epoch, credential class, and exact signature.

## Test vectors

> A generator script is available at `scripts/generate_vectors.go`.
> Run it to fill in actual vectors for the first release.

## Security assumptions

- The server protects `master_seed_hex` and `auth_secret` as high-value secrets.
- `use_memory_store` is for testing only; production must use Redis or persistent storage.
- Signatures are only valid for the exact `witness` point computed from the message.
- DLEQ proof ensures the server is signing with the derived key corresponding to the returned `public_key`.

## Current limitations and future work

- Document hash-to-curve DST behavior and edge cases in more detail.
- Clarify cross-domain replay protection assumptions and how class/epoch isolation interacts with key-rotation policies.
- Add protocol versioning, stronger admin isolation, and optional metadata fields for application-specific credential attestations.
