import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { blind, unblind, verifyProof } from './bls_blind';

const DST = new TextEncoder().encode('BCIS-V1-MESSAGE');
const message = new TextEncoder().encode('hello');

const { blinded, blindingFactor } = blind(message, DST);
const blindSignature = bls.G1.Point.BASE.toBytes(true);
const publicKey = bls.G2.Point.BASE.toBytes(true);
const proof = {
  r1: bls.G2.Point.BASE.toBytes(true),
  r2: bls.G1.Point.BASE.toBytes(true),
  s: new Uint8Array(32),
  c: new Uint8Array(32),
};

const valid = verifyProof(proof, blinded, blindSignature, publicKey);
const unblindedSig = unblind(blindSignature, blindingFactor);

console.log('proof valid', valid);
console.log('unblinded signature bytes', unblindedSig.length);