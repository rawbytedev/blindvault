import { blind, unblind, verifyProof } from './index';

function hexToBytes(hex: string): Uint8Array {
    const normalized = hex.replace(/^0x/, '');
    if (normalized.length % 2 !== 0) throw new Error('Hex string must have even length');
    const bytes = new Uint8Array(normalized.length / 2);
    for (let i = 0; i < normalized.length; i += 2) {
        bytes[i / 2] = Number.parseInt(normalized.slice(i, i + 2), 16);
    }
    return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

const vectors = {
    message: 'Hello BlindVault',
    dst: 'BCIS-V1-MESSAGE',
    blindingFactorHex: '120824998855f78ce925508a179df690ac5a9aecd8e6259955e5b4a918657d83',
    blindedHex: 'b70fc057d68a5027db5e6b72d608fdd640ae02061c30f1777fd71d19441f6bf2cdb4db498ca67cf9fb53943fe205ae61',
    blindSignatureHex: 'a2786bea268dea3be3af71e9536c23828438bba24e066fa9324e4d3e0ec439951284afecef8b46bdd855c95fed2a5956',
    publicKeyHex: '96f45d5f6cad1436ae595ad0957f3672abda331154c0d3a926225fe44898dd0a7e8d758901685632cef4138dad1424f41434f0aeb8dd6a07960bdc8651a6a69c48403c19fde9f6fc9244024946d40290bdd9eac8f85749dce9c5aa7a63c81795',
    proofR1Hex: 'a516ae6ad1fe1095220ff6d79844367b768eb3682bd071af3b9e799f993bc8669953ad0a2048a544897bf8d8e13cdd2714188230a33c8be18975f9aefeb75cd204b30b24d788aba3dee4386936edcfdf1f10e49b34072415f95355423af71d2a',
    proofR2Hex: 'a73257378b4a62d935c3a43e6efaadd3d07f08187605b9f08ea71c8760f33621aa0ef29004f5e0b3bcd308d0bb1f8c90',
    proofSHex: '6081c67d4697f0a8a9a364896296f7e3558d30b0af9a7ce7249b064e24cc6986',
    proofCHex: '6334500f62ec287aa92b6ec65f774dbc2f65c0f2519b5eb9820b3baba810c011',
    unblindedHex: 'a13f83f912bc124e7e0367244ff2cc048d4bffc99d35ed45a2030af62cf448647aaf5382f0e5df46cd889603b75ae9c1',
};

let lastBlind: { blinded: Uint8Array; witness: Uint8Array; blindingFactor: Uint8Array } | null = null;

export function runBlind() {
    try {
        const message = new TextEncoder().encode(vectors.message);
        const dst = new TextEncoder().encode(vectors.dst);
        const blindingFactor = hexToBytes(vectors.blindingFactorHex);

        const result = blind(message, dst, blindingFactor);
        lastBlind = result;

        const output = document.getElementById('blind-output');
        if (output) {
            output.innerHTML = `
        <div class="demo-code">
          <strong>Input:</strong><br>
          message: "${vectors.message}"<br>
          dst: "${vectors.dst}"<br>
          blindingFactor: ${vectors.blindingFactorHex.slice(0, 32)}...
        </div>
        <div class="demo-output">
          <strong>Output:</strong><br>
          blinded (hex): ${bytesToHex(result.blinded).slice(0, 64)}...<br>
          witness (hex): ${bytesToHex(result.witness).slice(0, 64)}...<br>
          blindingFactor (hex): ${bytesToHex(result.blindingFactor).slice(0, 32)}...<br>
          ✅ Matches documented vector: ${bytesToHex(result.blinded) === vectors.blindedHex ? 'YES' : 'NO'}
        </div>
      `;
        }
    } catch (err) {
        const output = document.getElementById('blind-output');
        if (output) {
            output.innerHTML = `<div class="demo-error">Error: ${(err as Error).message}</div>`;
        }
    }
}

export function runVerify() {
    try {
        const proof = {
            r1: hexToBytes(vectors.proofR1Hex),
            r2: hexToBytes(vectors.proofR2Hex),
            s: hexToBytes(vectors.proofSHex),
            c: hexToBytes(vectors.proofCHex),
        };
        const blinded = hexToBytes(vectors.blindedHex);
        const signature = hexToBytes(vectors.blindSignatureHex);
        const publicKey = hexToBytes(vectors.publicKeyHex);

        const isValid = verifyProof(proof, blinded, signature, publicKey);

        const output = document.getElementById('verify-output');
        if (output) {
            output.innerHTML = `
        <div class="demo-code">
          <strong>Verifying DLEQ proof with:</strong><br>
          blinded (hex): ${vectors.blindedHex.slice(0, 32)}...<br>
          signature (hex): ${vectors.blindSignatureHex.slice(0, 32)}...<br>
          publicKey (hex): ${vectors.publicKeyHex.slice(0, 32)}...
        </div>
        <div class="demo-output">
          <strong>Result:</strong><br>
          DLEQ Proof Valid: ${isValid ? '✅ YES' : '❌ NO'}
        </div>
      `;
        }
    } catch (err) {
        const output = document.getElementById('verify-output');
        if (output) {
            output.innerHTML = `<div class="demo-error">Error: ${(err as Error).message}</div>`;
        }
    }
}

export function runUnblind() {
    try {
        if (!lastBlind) {
            throw new Error('Run "Blind a Message" first');
        }

        const blindSignature = hexToBytes(vectors.blindSignatureHex);
        const unblinded = unblind(blindSignature, lastBlind.blindingFactor);

        const output = document.getElementById('unblind-output');
        if (output) {
            output.innerHTML = `
        <div class="demo-code">
          <strong>Unblinding with:</strong><br>
          blindSignature (hex): ${vectors.blindSignatureHex.slice(0, 32)}...<br>
          blindingFactor (hex): ${bytesToHex(lastBlind.blindingFactor).slice(0, 32)}...
        </div>
        <div class="demo-output">
          <strong>Result:</strong><br>
          unblindedSignature (hex): ${bytesToHex(unblinded)}<br>
          ✅ Matches documented vector: ${bytesToHex(unblinded) === vectors.unblindedHex ? 'YES' : 'NO'}
        </div>
      `;
        }
    } catch (err) {
        const output = document.getElementById('unblind-output');
        if (output) {
            output.innerHTML = `<div class="demo-error">Error: ${(err as Error).message}</div>`;
        }
    }
}

export function runFullFlow() {
    try {
        const message = new TextEncoder().encode(vectors.message);
        const dst = new TextEncoder().encode(vectors.dst);
        const blindingFactor = hexToBytes(vectors.blindingFactorHex);

        // Step 1: Blind
        const blindResult = blind(message, dst, blindingFactor);

        // Step 2: Verify proof
        const proof = {
            r1: hexToBytes(vectors.proofR1Hex),
            r2: hexToBytes(vectors.proofR2Hex),
            s: hexToBytes(vectors.proofSHex),
            c: hexToBytes(vectors.proofCHex),
        };
        const blindSignature = hexToBytes(vectors.blindSignatureHex);
        const publicKey = hexToBytes(vectors.publicKeyHex);
        const isProofValid = verifyProof(proof, blindResult.blinded, blindSignature, publicKey);

        // Step 3: Unblind
        const unblinded = unblind(blindSignature, blindResult.blindingFactor);

        const output = document.getElementById('full-output');
        if (output) {
            output.innerHTML = `
        <div class="demo-output">
          <strong>Complete Blind-Signature Workflow:</strong><br><br>
          ✅ Step 1 - Blind message:<br>
          &nbsp;&nbsp;blinded: ${bytesToHex(blindResult.blinded).slice(0, 48)}...<br><br>
          ${isProofValid ? '✅' : '❌'} Step 2 - Verify DLEQ proof: ${isProofValid ? 'VALID' : 'INVALID'}<br><br>
          ✅ Step 3 - Unblind signature:<br>
          &nbsp;&nbsp;unblinded: ${bytesToHex(unblinded).slice(0, 48)}...<br><br>
          <strong>Verification against documented vectors:</strong><br>
          • blinded matches: ${bytesToHex(blindResult.blinded) === vectors.blindedHex ? '✅' : '❌'}<br>
          • unblinded matches: ${bytesToHex(unblinded) === vectors.unblindedHex ? '✅' : '❌'}<br>
        </div>
      `;
        }
    } catch (err) {
        const output = document.getElementById('full-output');
        if (output) {
            output.innerHTML = `<div class="demo-error">Error: ${(err as Error).message}</div>`;
        }
    }
}

// Expose functions to global scope for onclick handlers
(window as any).runBlind = runBlind;
(window as any).runVerify = runVerify;
(window as any).runUnblind = runUnblind;
(window as any).runFullFlow = runFullFlow;
