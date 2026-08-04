// ------------------------------------------------------------------
// Utility functions
// ------------------------------------------------------------------

export function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.replace(/^0x/, '');
  if (normalized.length % 2 !== 0) throw new Error('Hex string must have even length');
  const bytes = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < normalized.length; i += 2) {
    bytes[i / 2] = Number.parseInt(normalized.slice(i, i + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

// ------------------------------------------------------------------
// Encryption / Decryption (E2E)
// ------------------------------------------------------------------

export async function encryptCredential(plaintextObj: any, storageKey: Uint8Array): Promise<string> {
  const plaintext = JSON.stringify(plaintextObj);
  const encoder = new TextEncoder();
  const data = encoder.encode(plaintext);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cryptoKey = await crypto.subtle.importKey(
    "raw", storageKey.buffer as ArrayBuffer, { name: "AES-GCM" }, false, ["encrypt"]
  );
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    cryptoKey,
    data
  );
  const combined = new Uint8Array([...iv, ...new Uint8Array(ciphertext)]);
  return bytesToHex(combined);
}

export async function decryptCredential(ciphertextHex: string, storageKey: Uint8Array): Promise<any> {
  const combined = hexToBytes(ciphertextHex);
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  const cryptoKey = await crypto.subtle.importKey(
    "raw", storageKey.buffer as ArrayBuffer, { name: "AES-GCM" }, false, ["decrypt"]
  );
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    cryptoKey,
    ciphertext
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
}

// ------------------------------------------------------------------
// JWT generation using HMAC-SHA256
// ------------------------------------------------------------------

export async function generateJWT(secret: string, credentialClass: string): Promise<string> {
  if (!secret) return '';

  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: credentialClass,
    iat: now,
    exp: now + 300, // 5 minutes expiry
    iss: 'blindvault-client',
  };

  const base64UrlEncode = (obj: object): string => {
    const json = JSON.stringify(obj);
    const bytes = new TextEncoder().encode(json);
    const base64 = btoa(String.fromCharCode(...bytes));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };

  const headerB64 = base64UrlEncode(header);
  const payloadB64 = base64UrlEncode(payload);
  const data = `${headerB64}.${payloadB64}`;

  const keyData = new TextEncoder().encode(secret);
  const messageData = new TextEncoder().encode(data);
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign('HMAC', cryptoKey, messageData);
  const signatureArray = new Uint8Array(signature);
  const signatureB64 = btoa(String.fromCharCode(...signatureArray))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  return `${data}.${signatureB64}`;
}
