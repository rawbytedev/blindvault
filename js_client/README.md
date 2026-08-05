# BlindVault JS Client SDK

This package provides a small TypeScript SDK for the blind-signature flow used by BlindVault.
It lets a client blind a message for issuance, verify the issuer's DLEQ proof, and unblind the final signature.

## Installation

Install from npm:

```bash
npm install blindvault-js-client-sdk
```

## API

The package exports:

- `blind(message, dst, blindingFactor?)`
- `unblind(blindSignature, blindingFactor)`
- `verifyProof(proof, blinded, signature, publicKey)`

## Basic usage

```ts
import { blind, unblind, verifyProof } from 'blindvault-js-client-sdk';

const dst = new TextEncoder().encode('BCIS-V1-MESSAGE');
const message = new TextEncoder().encode('Hello BlindVault');

const { blinded, blindingFactor } = blind(message, dst);

// Send `blinded` to the issuer and receive:
// - blindSignature
// - publicKey
// - proof

const isValid = verifyProof(proof, blinded, blindSignature, publicKey);
if (!isValid) {
  throw new Error('DLEQ proof is invalid');
}

const unblindedSignature = unblind(blindSignature, blindingFactor);
console.log(unblindedSignature);
```

## Notes on the protocol

- `blind()` returns the blinded point and the blinding material needed to unblind later.
- `unblind()` removes the blinding factor from the issuer-issued blind signature.
- `verifyProof()` checks the issuer's DLEQ proof without contacting the server.

## Verification

The implementation is covered by deterministic regression tests that validate the SDK against the crypto vectors documented in [docs/crypto_vectors.md](../docs/crypto_vectors.md).

## Development

```bash
npm install
npm test
npm run build
npm run build:lib
npm run build:browser
npm run pack
```
