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
        const blinded = hexToBytes('833e3ac5d47ada8cee5863a307efb95c7e0977d41c9e6daa6440a72698b8718a711a46402b0d45e7e6add79bb5d8ac30');
        const blindSignature = hexToBytes('85783f115941aaa09eff29813ac90503e79e754d2799a8aac59449b05b8b3502a7743989bdeafc9807d9512dddb18036');
        const publicKey = hexToBytes('a4da95ea6b9dfd5e05a0d25d163a6a486896815a5add989faa1076208f8c856ab7e833ba738ba161b9e689c5921804e30ddd554b3ad8ce2afbab07bb3d55b7d7fecfb241d9627011c1aa868fd6cdd051d6a10ca3b48c39d69bd2691cc6a680fd');
        const proof = {
            r1: hexToBytes('85d6243bef8d93ab37ccdede6a4c64f38d70764138e6c1e6f9e9f8db7ba74e9d839e6dcebdfe248347ab6ef6d6d45b3b0a9522ba939b3a64f63e18e660e13be108a13b51c5dc4a20d1935f540f48665e3a33e2279a67905d6bf140e1e0e8d22b'),
            r2: hexToBytes('b823955d8c7db67ecca035a4bd5e500a54bce51948e129bae3eda8a8831bd8e2ff87b0f24f1cfd1839c998873728a6fa'),
            s: hexToBytes('625d4c2f936f6906f751eceaaf918f222cd9a140753eec51d23fc3c40e2e6c62'),
            c: hexToBytes('729c4288334a23db9aa254c8011a3c5c0515d12fc41f94afce8798b90f1aacaa'),
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
