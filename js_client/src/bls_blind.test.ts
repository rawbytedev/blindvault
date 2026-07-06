import { describe, expect, it } from 'vitest';
import { blind, unblind, verifyProof } from './bls_blind';

function hexToBytes(hex: string): Uint8Array {
    const normalized = hex.replace(/^0x/, '');
    if (normalized.length % 2 !== 0) {
        throw new Error('Hex string must have an even length');
    }
    const bytes = new Uint8Array(normalized.length / 2);
    for (let i = 0; i < normalized.length; i += 2) {
        bytes[i / 2] = Number.parseInt(normalized.slice(i, i + 2), 16);
    }
    return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

describe('blindvault JS client SDK', () => {
    it('matches the documented blind-signature vectors', () => {
        const message = new TextEncoder().encode('Hello BlindVault');
        const dst = new TextEncoder().encode('BCIS-V1-MESSAGE');
        const witness = hexToBytes('a61653518870b2b7d2def1f78a8ab21f17f9b9bc6d7ca9a0d744f6150227311acd50d3bdc6ffa8dc52567ee4c6e5dcb7');
        const blinded = hexToBytes('a8b66ce1f5a1b415cb93a94d2387411c7628e0fb575dbb0c41b782832595c22a675d8bad8b2134ac5dbbdc3fbce6602e');
        const blindSignature = hexToBytes('a3c8833609f701404702683ab67a324ae304accd087ee598ad35a2cf4f9290f7a5b83bc62a1474f5d05a7ccfbf2964bb');
        const publicKey = hexToBytes('96f45d5f6cad1436ae595ad0957f3672abda331154c0d3a926225fe44898dd0a7e8d758901685632cef4138dad1424f41434f0aeb8dd6a07960bdc8651a6a69c48403c19fde9f6fc9244024946d40290bdd9eac8f85749dce9c5aa7a63c81795');
        const proof = {
            r1: hexToBytes('8cb14854bb4daf5e74ee19e39edb84b0ae2553be3866e8420ca95bee522487cd252d5d4c9c9f3d6767e7d7c733e4cba919c56fda85760332ee20af69eb7affec14c2d20727efecbfdd39736bcf089d46e3da782033eb0821e866a9a2a254292d'),
            r2: hexToBytes('a40b52f34d6cec3ec294726ea97a92807d636a2a117ea6ec5882637a8fe703a2b75d96431bfe9066a7dfba2ac4db2b36'),
            s: hexToBytes('038b102b9b80f1256caa186022789ea4a0f1ff404ad22c2b686f9260e069bbf5'),
            c: hexToBytes('6d4f47de45a45250e2c16381b096d50c8b0c537147460ec1c47f4bd5604258ec'),
        };

        const result = blind(message, dst);
        expect(bytesToHex(result.witness)).toBe(bytesToHex(witness));
        expect(result.blindingFactor).toHaveLength(32);

        const isProofValid = verifyProof(proof, blinded, blindSignature, publicKey);
        expect(isProofValid).toBe(true);

        const unblindedWitness = unblind(result.blinded, result.blindingFactor);
        expect(bytesToHex(unblindedWitness)).toBe(bytesToHex(result.witness));
    });
});
