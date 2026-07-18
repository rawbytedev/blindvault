import { bls12_381 as bls } from '@noble/curves/bls12-381.js';

const DLEQ_PROOF_DST = new TextEncoder().encode('BCIS-V1-DLEQ-CHALLENGE');

function deserializeG1(bytes: Uint8Array): ReturnType<typeof bls.G1.Point.fromBytes> {
  try {
    return bls.G1.Point.fromBytes(bytes);
  } catch {
    throw new Error('Invalid G1 point');
  }
}

function deserializeG2(bytes: Uint8Array): ReturnType<typeof bls.G2.Point.fromBytes> {
  try {
    return bls.G2.Point.fromBytes(bytes);
  } catch {
    throw new Error('Invalid G2 point');
  }
}

function deserializeScalar(bytes: Uint8Array): bigint {
  if (bytes.length !== 32) throw new Error('Scalar must be 32 bytes');
  return bls.fields.Fr.fromBytes(bytes);
}

function serializeScalar(value: bigint): Uint8Array {
  return bls.fields.Fr.toBytes(value);
}

function serializePoint(point: ReturnType<typeof bls.G1.Point.fromBytes>): Uint8Array {
  return point.toBytes(true);
}

function serializePointG2(point: ReturnType<typeof bls.G2.Point.fromBytes>): Uint8Array {
  return point.toBytes(true);
}

export function blind(message: Uint8Array, dst: Uint8Array, blindingFactor?: Uint8Array): {
  blinded: Uint8Array;
  witness: Uint8Array;
  blindingFactor: Uint8Array;
} {
  const point = bls.G1.hashToCurve(message, { DST: dst });
  const r = blindingFactor
    ? deserializeScalar(blindingFactor)
    : (() => {
      const randomBytes = new Uint8Array(32);
      crypto.getRandomValues(randomBytes);
      return bls.fields.Fr.fromBytes(randomBytes);
    })();

  const blinded = point.multiply(r);
  return {
    blinded: serializePoint(blinded),
    witness: serializePoint(point),
    blindingFactor: serializeScalar(r),
  };
}

export function unblind(blindSignature: Uint8Array, blindingFactor: Uint8Array): Uint8Array {
  const sigPoint = deserializeG1(blindSignature);
  const r = deserializeScalar(blindingFactor);
  const rInv = bls.fields.Fr.inv(r);
  const unblinded = sigPoint.multiply(rInv);
  return serializePoint(unblinded);
}

export interface DLEQProof {
  r1: Uint8Array;
  r2: Uint8Array;
  s: Uint8Array;
  c: Uint8Array;
}

function computeChallenge(
  r1: ReturnType<typeof bls.G2.Point.fromBytes>,
  r2: ReturnType<typeof bls.G1.Point.fromBytes>,
  pk: ReturnType<typeof bls.G2.Point.fromBytes>,
  blinded: ReturnType<typeof bls.G1.Point.fromBytes>,
  sig: ReturnType<typeof bls.G1.Point.fromBytes>
): bigint {
  const parts = [
    serializePointG2(r1),
    serializePoint(r2),
    serializePointG2(pk),
    serializePoint(blinded),
    serializePoint(sig),
  ];
  const totalLen = parts.reduce((sum, p) => sum + p.length, 0);
  const data = new Uint8Array(totalLen);
  let offset = 0;
  for (const p of parts) {
    data.set(p, offset);
    offset += p.length;
  }
  return bls.G1.hashToScalar(data, { DST: DLEQ_PROOF_DST });
}

export function verifyProof(
  proof: DLEQProof,
  blinded: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): boolean {
  try {
    const r1 = deserializeG2(proof.r1);
    const r2 = deserializeG1(proof.r2);
    const s = deserializeScalar(proof.s);
    const c = deserializeScalar(proof.c);
    const blindedPoint = deserializeG1(blinded);
    const sigPoint = deserializeG1(signature);
    const pkPoint = deserializeG2(publicKey);

    const cPrime = computeChallenge(r1, r2, pkPoint, blindedPoint, sigPoint);
    if (c !== cPrime) return false;

    const g2 = bls.G2.Point.BASE;
    const left1 = g2.multiply(s);
    const right1 = r1.add(pkPoint.multiply(c));
    if (!left1.equals(right1)) return false;

    const left2 = blindedPoint.multiply(s);
    const right2 = r2.add(sigPoint.multiply(c));
    return left2.equals(right2);
  } catch {
    return false;
  }
}