import { blind, unblind, verifyProof, hexToBytes, bytesToHex, encryptCredential, decryptCredential, generateJWT } from './index';
// ===================================================================
// CONSTANTS & UTILITIES
// ===================================================================

const APP_CONTEXT = "airdrop_2026_q3";
const BLIND_SALT = "BLINDVAULT-V1-BLINDING";
const STORAGE_SALT = "BLINDVAULT-STORAGE-V1";

// ------------------------------------------------------------------
// Deterministic derivation functions
// ------------------------------------------------------------------

async function deriveBlindingScalar(walletSignatureHex: string): Promise<Uint8Array> {
  const signatureBytes = hexToBytes(walletSignatureHex);
  const encoder = new TextEncoder();
  const contextBytes = encoder.encode(APP_CONTEXT + BLIND_SALT);
  const combined = new Uint8Array([...signatureBytes, ...contextBytes]);
  const hashBuffer = await crypto.subtle.digest("SHA-256", combined);
  return new Uint8Array(hashBuffer);
}

async function deriveStorageKey(walletSignatureHex: string): Promise<Uint8Array> {
  const signatureBytes = hexToBytes(walletSignatureHex);
  const encoder = new TextEncoder();
  const contextBytes = encoder.encode(APP_CONTEXT + STORAGE_SALT);
  const combined = new Uint8Array([...signatureBytes, ...contextBytes]);
  const hashBuffer = await crypto.subtle.digest("SHA-256", combined);
  return new Uint8Array(hashBuffer);
}


// ===================================================================
// VECTOR MODE (unchanged)
// ===================================================================

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
          blindingFactor: ${vectors.blindingFactorHex.slice(0, 32)}…
        </div>
        <div class="demo-output">
          <strong>Output:</strong><br>
          blinded (hex): ${bytesToHex(result.blinded).slice(0, 64)}…<br>
          witness (hex): ${bytesToHex(result.witness).slice(0, 64)}…<br>
          blindingFactor (hex): ${bytesToHex(result.blindingFactor).slice(0, 32)}…<br>
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
          blinded (hex): ${vectors.blindedHex.slice(0, 32)}…<br>
          signature (hex): ${vectors.blindSignatureHex.slice(0, 32)}…<br>
          publicKey (hex): ${vectors.publicKeyHex.slice(0, 32)}…
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
          blindSignature (hex): ${vectors.blindSignatureHex.slice(0, 32)}…<br>
          blindingFactor (hex): ${bytesToHex(lastBlind.blindingFactor).slice(0, 32)}…
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

    const blindResult = blind(message, dst, blindingFactor);

    const proof = {
      r1: hexToBytes(vectors.proofR1Hex),
      r2: hexToBytes(vectors.proofR2Hex),
      s: hexToBytes(vectors.proofSHex),
      c: hexToBytes(vectors.proofCHex),
    };
    const blindSignature = hexToBytes(vectors.blindSignatureHex);
    const publicKey = hexToBytes(vectors.publicKeyHex);
    const isProofValid = verifyProof(proof, blindResult.blinded, blindSignature, publicKey);

    const unblinded = unblind(blindSignature, blindResult.blindingFactor);

    const output = document.getElementById('full-output');
    if (output) {
      output.innerHTML = `
        <div class="demo-output">
          <strong>Complete Blind-Signature Workflow:</strong><br><br>
          ✅ Step 1 - Blind message:<br>
          &nbsp;&nbsp;blinded: ${bytesToHex(blindResult.blinded).slice(0, 48)}…<br><br>
          ${isProofValid ? '✅' : '❌'} Step 2 - Verify DLEQ proof: ${isProofValid ? 'VALID' : 'INVALID'}<br><br>
          ✅ Step 3 - Unblind signature:<br>
          &nbsp;&nbsp;unblinded: ${bytesToHex(unblinded).slice(0, 48)}…<br><br>
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

// ===================================================================
// SHARED HELPERS 
// ===================================================================

interface ModeState {
  blinded?: Uint8Array;
  witness?: Uint8Array;
  blindingFactor?: Uint8Array;
  blindSignature?: Uint8Array;
  publicKey?: Uint8Array;
  keyEpoch?: string;
  proof?: { r1: Uint8Array; r2: Uint8Array; s: Uint8Array; c: Uint8Array };
  unblinded?: Uint8Array;
  jwtToken?: string;
}

type ModeInputs = {
  message: string;
  dst: string;
  server: string;
  credentialClass: string;
  token: string;
  secret: string;
  walletSig?: string;
};

async function performBlind(
  state: ModeState,
  inputs: ModeInputs,
  elementPrefix: string,
  useDeterministic: boolean
): Promise<void> {
  const msg = new TextEncoder().encode(inputs.message);
  const encDst = new TextEncoder().encode(inputs.dst);

  // Generate JWT if secret provided
  const tokenInput = document.getElementById(`${elementPrefix}-token`) as HTMLInputElement;
  if (inputs.secret && !tokenInput.value) {
    const jwt = await generateJWT(inputs.secret, inputs.credentialClass);
    tokenInput.value = jwt;
    state.jwtToken = jwt;
  } else if (tokenInput.value) {
    state.jwtToken = tokenInput.value;
  }

  // Blind – either deterministic or random
  let blindingFactor: Uint8Array | undefined;
  if (useDeterministic && inputs.walletSig) {
    blindingFactor = await deriveBlindingScalar(inputs.walletSig);
  }
  const result = blind(msg, encDst, blindingFactor);
  state.blinded = result.blinded;
  state.witness = result.witness;
  state.blindingFactor = result.blindingFactor;

  // Show issue card, hide others
  document.getElementById(`${elementPrefix}-issue-card`)!.style.display = 'block';
  document.getElementById(`${elementPrefix}-unblind-card`)!.style.display = 'none';
  document.getElementById(`${elementPrefix}-redeem-card`)!.style.display = 'none';
  document.getElementById(`${elementPrefix}-store-card`)!.style.display = 'none';
  document.getElementById(`${elementPrefix}-redeem-ticket-card`)!.style.display = 'none';
  (document.getElementById(`${elementPrefix}-verify-btn`) as HTMLButtonElement).disabled = true;

  const out = document.getElementById(`${elementPrefix}-blind-output`)!;
  out.className = 'output-box success';
  out.innerHTML = `
    <strong>✅ Blind succeeded ${useDeterministic ? '(deterministic)' : '(random)'}</strong><br/>
    blinded (hex): ${bytesToHex(result.blinded)}<br/>
    witness (hex): ${bytesToHex(result.witness)}<br/>
    blindingFactor (hex): ${bytesToHex(result.blindingFactor)}<br/>
    ${state.jwtToken ? '🔑 JWT token generated from shared secret' : ''}
    <span class="status-badge success">Ready to issue</span>
  `;
}

async function performIssue(state: ModeState, inputs: ModeInputs, elementPrefix: string): Promise<void> {
  if (!state.blinded) throw new Error('Please blind a message first');
  if (!inputs.credentialClass) throw new Error('Credential class is required');

  const authToken = state.jwtToken || inputs.token;
  const url = inputs.server + '/v1/credential/issue';
  const body = JSON.stringify({
    blinded_message: bytesToHex(state.blinded),
    credential_class: inputs.credentialClass,
  });

  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (authToken) {
    headers['Authorization'] = authToken.startsWith('Bearer ') ? authToken : 'Bearer ' + authToken;
  }

  const response = await fetch(url, { method: 'POST', headers, body });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(`Server error ${response.status}: ${text}`);
  }

  const data = await response.json();
  if (!data.blind_signature || !data.public_key || !data.proof) {
    throw new Error('Server response missing required fields');
  }

  state.blindSignature = hexToBytes(data.blind_signature);
  state.publicKey = hexToBytes(data.public_key);
  state.keyEpoch = data.key_epoch || '2026-01';
  state.proof = {
    r1: hexToBytes(data.proof.r1),
    r2: hexToBytes(data.proof.r2),
    s: hexToBytes(data.proof.s),
    c: hexToBytes(data.proof.c),
  };

  (document.getElementById(`${elementPrefix}-verify-btn`) as HTMLButtonElement).disabled = false;
  document.getElementById(`${elementPrefix}-unblind-card`)!.style.display = 'block';

  const out = document.getElementById(`${elementPrefix}-issue-output`)!;
  out.className = 'output-box success';
  out.innerHTML = `
    <strong>✅ Issued successfully</strong><br/>
    blindSignature (hex): ${data.blind_signature.slice(0, 64)}…<br/>
    publicKey (hex): ${data.public_key.slice(0, 64)}…<br/>
    keyEpoch: ${state.keyEpoch}<br/>
    <span class="status-badge success">Ready to verify proof</span>
  `;
}

function performVerifyProof(state: ModeState, elementPrefix: string): void {
  if (!state.proof || !state.blinded || !state.blindSignature || !state.publicKey) {
    throw new Error('Missing data. Please issue first.');
  }
  const valid = verifyProof(
    state.proof,
    state.blinded,
    state.blindSignature,
    state.publicKey
  );

  const out = document.getElementById(`${elementPrefix}-issue-output`)!;
  out.className = 'output-box ' + (valid ? 'success' : 'error');
  out.innerHTML = `
    <strong>${valid ? '✅ DLEQ proof is valid' : '❌ DLEQ proof is invalid'}</strong><br/>
    Verified against server-provided public key.
  `;
  if (!valid) {
    (document.getElementById(`${elementPrefix}-verify-btn`) as HTMLButtonElement).disabled = true;
  }
}

function performUnblind(state: ModeState, elementPrefix: string): void {
  if (!state.blindSignature || !state.blindingFactor) {
    throw new Error('Missing blind signature or blinding factor. Please issue first.');
  }
  const unblinded = unblind(state.blindSignature, state.blindingFactor);
  state.unblinded = unblinded;

  // Show appropriate next cards based on mode (core or airdrop)
  document.getElementById(`${elementPrefix}-redeem-card`)!.style.display = 'block';
  document.getElementById(`${elementPrefix}-store-card`)!.style.display = 'none';

  const out = document.getElementById(`${elementPrefix}-unblind-output`)!;
  out.className = 'output-box success';
  out.innerHTML = `
    <strong>✅ Unblinded signature</strong><br/>
    unblinded (hex): ${bytesToHex(unblinded)}<br/>
    <span class="status-badge success">Ready to redeem</span>
  `;
}

async function performRedeem(state: ModeState, inputs: ModeInputs, elementPrefix: string): Promise<void> {
  if (!state.unblinded || !state.witness || !state.keyEpoch) {
    throw new Error('Missing data. Please unblind first.');
  }
  if (!inputs.credentialClass) throw new Error('Credential class is required');

  const authToken = state.jwtToken || inputs.token;
  const url = inputs.server + '/v1/credential/consume';
  const body = JSON.stringify({
    unblinded_signature: bytesToHex(state.unblinded),
    witness: bytesToHex(state.witness),
    credential_class: inputs.credentialClass,
    key_epoch: state.keyEpoch,
  });

  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (authToken) {
    headers['Authorization'] = authToken.startsWith('Bearer ') ? authToken : 'Bearer ' + authToken;
  }

  const response = await fetch(url, { method: 'POST', headers, body });

  let success = false;
  let msg = '';
  if (response.ok) {
    const result = await response.json();
    success = result.valid === true;
    msg = success ? 'Credential accepted!' : 'Credential rejected (invalid)';
  } else if (response.status === 409) {
    const errData = await response.json();
    msg = 'Conflict: ' + (errData.error || 'credential already redeemed');
  } else {
    const text = await response.text();
    throw new Error(`Server error ${response.status}: ${text}`);
  }

  const out = document.getElementById(`${elementPrefix}-redeem-output`)!;
  out.className = 'output-box ' + (success ? 'success' : 'error');
  out.innerHTML = `
    <strong>${success ? '✅ Redeemed successfully' : '❌ Redemption failed'}</strong><br/>
    ${msg}
  `;
}

// ===================================================================
// CORE API MODE
// ===================================================================

interface CoreState extends ModeState { }
const coreState: CoreState = {};

function getCoreInputs(): ModeInputs {
  return {
    message: (document.getElementById('core-message') as HTMLInputElement).value,
    dst: (document.getElementById('core-dst') as HTMLInputElement).value,
    server: (document.getElementById('core-server') as HTMLInputElement).value,
    credentialClass: (document.getElementById('core-class') as HTMLInputElement).value,
    token: (document.getElementById('core-token') as HTMLInputElement).value,
    secret: (document.getElementById('core-secret') as HTMLInputElement).value,
  };
}

export async function coreBlind() {
  try {
    await performBlind(coreState, getCoreInputs(), 'core', false);
  } catch (err) {
    const out = document.getElementById('core-blind-output')!;
    out.className = 'output-box error';
    out.textContent = `Error: ${(err as Error).message}`;
  }
}

export async function coreIssue() {
  try {
    await performIssue(coreState, getCoreInputs(), 'core');
  } catch (err) {
    const out = document.getElementById('core-issue-output')!;
    out.className = 'output-box error';
    out.textContent = 'Error: ' + (err as Error).message;
  }
}

export function coreVerifyProof() {
  try {
    performVerifyProof(coreState, 'core');
  } catch (err) {
    const out = document.getElementById('core-issue-output')!;
    out.className = 'output-box error';
    out.textContent = 'Error: ' + (err as Error).message;
  }
}

export function coreUnblind() {
  try {
    performUnblind(coreState, 'core');
  } catch (err) {
    const out = document.getElementById('core-unblind-output')!;
    out.className = 'output-box error';
    out.textContent = 'Error: ' + (err as Error).message;
  }
}

export async function coreRedeem() {
  try {
    await performRedeem(coreState, getCoreInputs(), 'core');
  } catch (err) {
    const out = document.getElementById('core-redeem-output')!;
    out.className = 'output-box error';
    out.textContent = 'Error: ' + (err as Error).message;
  }
}

// ===================================================================
// AIRDROP DEMO MODE
// ===================================================================

interface AirdropState extends ModeState { }
const airdropState: AirdropState = {};

function getAirdropInputs(): ModeInputs {
  return {
    message: (document.getElementById('airdrop-message') as HTMLInputElement).value,
    dst: (document.getElementById('airdrop-dst') as HTMLInputElement).value,
    server: (document.getElementById('airdrop-server') as HTMLInputElement).value,
    credentialClass: (document.getElementById('airdrop-class') as HTMLInputElement).value,
    token: (document.getElementById('airdrop-token') as HTMLInputElement).value,
    secret: (document.getElementById('airdrop-secret') as HTMLInputElement).value,
    walletSig: (document.getElementById('airdrop-wallet-sig') as HTMLInputElement).value,
  };
}

export async function airdropBlind() {
  try {
    const inputs = getAirdropInputs();
    if (!inputs.walletSig) {
      throw new Error('Wallet signature is required for deterministic blinding');
    }
    await performBlind(airdropState, inputs, 'airdrop', true);
  } catch (err) {
    const out = document.getElementById('airdrop-blind-output')!;
    out.className = 'output-box error';
    out.textContent = `Error: ${(err as Error).message}`;
  }
}

export async function airdropIssue() {
  try {
    await performIssue(airdropState, getAirdropInputs(), 'airdrop');
  } catch (err) {
    const out = document.getElementById('airdrop-issue-output')!;
    out.className = 'output-box error';
    out.textContent = 'Error: ' + (err as Error).message;
  }
}

export function airdropVerifyProof() {
  try {
    performVerifyProof(airdropState, 'airdrop');
  } catch (err) {
    const out = document.getElementById('airdrop-issue-output')!;
    out.className = 'output-box error';
    out.textContent = 'Error: ' + (err as Error).message;
  }
}

export function airdropUnblind() {
  try {
    if (!airdropState.blindSignature || !airdropState.blindingFactor) {
      throw new Error('Missing blind signature or blinding factor. Please issue first.');
    }
    const unblinded = unblind(airdropState.blindSignature, airdropState.blindingFactor);
    airdropState.unblinded = unblinded;

    // In airdrop mode, show the store card instead of direct redeem
    document.getElementById('airdrop-store-card')!.style.display = 'block';
    document.getElementById('airdrop-redeem-card')!.style.display = 'none';
    document.getElementById('airdrop-redeem-ticket-card')!.style.display = 'none';

    const out = document.getElementById('airdrop-unblind-output')!;
    out.className = 'output-box success';
    out.innerHTML = `
      <strong>✅ Unblinded signature</strong><br/>
      unblinded (hex): ${bytesToHex(unblinded)}<br/>
      <span class="status-badge success">Ready to store</span>
    `;
  } catch (err) {
    const out = document.getElementById('airdrop-unblind-output')!;
    out.className = 'output-box error';
    out.textContent = 'Error: ' + (err as Error).message;
  }
}

export async function airdropStore() {
  try {
    if (!airdropState.unblinded || !airdropState.witness || !airdropState.keyEpoch) {
      throw new Error('Missing data. Please unblind first.');
    }
    const { server, credentialClass, walletSig } = getAirdropInputs();
    if (!walletSig) {
      throw new Error('Wallet signature is required for encryption key');
    }

    const storageKey = await deriveStorageKey(walletSig);
    const credential = {
      sig: bytesToHex(airdropState.unblinded),
      witness: bytesToHex(airdropState.witness),
      class: credentialClass,
      epoch: airdropState.keyEpoch,
    };
    const ciphertext = await encryptCredential(credential, storageKey);

    const url = server + '/demo/store';
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ciphertext }),
    });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Store failed: ${response.status} ${text}`);
    }
    const data = await response.json();
    const ticketId = data.ticket_id;

    (document.getElementById('airdrop-ticket-id') as HTMLInputElement).value = ticketId;
    document.getElementById('airdrop-redeem-ticket-card')!.style.display = 'block';

    const out = document.getElementById('airdrop-store-output')!;
    out.className = 'output-box success';
    out.innerHTML = `
      <strong>✅ Credential stored securely</strong><br/>
      Ticket ID: <code>${ticketId}</code><br/>
      <span class="status-badge success">You can now redeem using this ticket ID</span>
    `;
  } catch (err) {
    const out = document.getElementById('airdrop-store-output')!;
    out.className = 'output-box error';
    out.textContent = 'Error: ' + (err as Error).message;
  }
}

export async function airdropRedeemTicket() {
  try {
    const { server, walletSig } = getAirdropInputs();
    const ticketId = (document.getElementById('airdrop-ticket-id') as HTMLInputElement).value.trim();
    if (!ticketId) throw new Error('Please enter a ticket ID');
    if (!walletSig) throw new Error('Wallet signature is required for decryption');

    const url = server + `/demo/retrieve?ticket_id=${encodeURIComponent(ticketId)}`;
    const resp = await fetch(url);
    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`Fetch failed: ${resp.status} ${text}`);
    }
    const data = await resp.json();
    if (!data.ciphertext) throw new Error('No ciphertext found for this ticket');

    const storageKey = await deriveStorageKey(walletSig);
    const credential = await decryptCredential(data.ciphertext, storageKey);
    if (!credential.sig || !credential.witness || !credential.class || !credential.epoch) {
      throw new Error('Decrypted credential missing required fields');
    }

    const consumeUrl = server + '/v1/credential/consume';
    const body = JSON.stringify({
      unblinded_signature: credential.sig,
      witness: credential.witness,
      credential_class: credential.class,
      key_epoch: credential.epoch,
    });
    const consumeResp = await fetch(consumeUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
    });

    let success = false;
    let msg = '';
    if (consumeResp.ok) {
      const result = await consumeResp.json();
      success = result.valid === true;
      msg = success ? 'Credential accepted!' : 'Credential rejected (invalid)';
    } else if (consumeResp.status === 409) {
      const errData = await consumeResp.json();
      msg = 'Conflict: ' + (errData.error || 'credential already redeemed');
    } else {
      const text = await consumeResp.text();
      throw new Error(`Redeem failed: ${consumeResp.status} ${text}`);
    }

    const out = document.getElementById('airdrop-redeem-ticket-output')!;
    out.className = 'output-box ' + (success ? 'success' : 'error');
    out.innerHTML = `
      <strong>${success ? '✅ Redeemed successfully' : '❌ Redemption failed'}</strong><br/>
      ${msg}
    `;
  } catch (err) {
    const out = document.getElementById('airdrop-redeem-ticket-output')!;
    out.className = 'output-box error';
    out.textContent = 'Error: ' + (err as Error).message;
  }
}

// ===================================================================
// MODE SWITCHING
// ===================================================================

export function switchMode(mode: 'vector' | 'core' | 'airdrop') {
  const vectorEl = document.getElementById('vector-mode')!;
  const coreEl = document.getElementById('core-mode')!;
  const airdropEl = document.getElementById('airdrop-mode')!;
  vectorEl.classList.remove('visible');
  coreEl.classList.remove('visible');
  airdropEl.classList.remove('visible');
  if (mode === 'vector') vectorEl.classList.add('visible');
  else if (mode === 'core') coreEl.classList.add('visible');
  else if (mode === 'airdrop') airdropEl.classList.add('visible');
}

// ===================================================================
// GLOBAL EXPOSURE
// ===================================================================

(window as any).runBlind = runBlind;
(window as any).runVerify = runVerify;
(window as any).runUnblind = runUnblind;
(window as any).runFullFlow = runFullFlow;

(window as any).coreBlind = coreBlind;
(window as any).coreIssue = coreIssue;
(window as any).coreVerifyProof = coreVerifyProof;
(window as any).coreUnblind = coreUnblind;
(window as any).coreRedeem = coreRedeem;

(window as any).airdropBlind = airdropBlind;
(window as any).airdropIssue = airdropIssue;
(window as any).airdropVerifyProof = airdropVerifyProof;
(window as any).airdropUnblind = airdropUnblind;
(window as any).airdropStore = airdropStore;
(window as any).airdropRedeemTicket = airdropRedeemTicket;

(window as any).switchMode = switchMode;