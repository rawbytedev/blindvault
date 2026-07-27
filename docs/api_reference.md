# API Reference

## Endpoints

### `POST /v1/credential/issue`

Issue a blind credential and receive a blind signature with proof.

- **Authentication:** required via `Authorization: Bearer <token>`
- **Request Content-Type:** `application/json`

#### Request body

```json
{
  "blinded_message": "<hex-encoded compressed G1 point>",
  "credential_class": "<credential class>"
}
```

Fields:
- `blinded_message`: hex‑encoded compressed G1 point created by client blinding.
- `credential_class`: application namespace used for key derivation (e.g., `airdrop_2026`, `tier_gold`).

#### Success response (200)

```json
{
  "blind_signature": "<hex-encoded compressed G1 point>",
  "public_key": "<hex-encoded compressed G2 point>",
  "key_epoch": "<epoch>",
  "proof": {
    "r1": "<hex-encoded compressed G2 point>",
    "r2": "<hex-encoded compressed G1 point>",
    "s": "<hex-encoded scalar>",
    "c": "<hex-encoded scalar>"
  }
}
```

#### Error responses

| Status | Description |
|--------|-------------|
| `400 Bad Request` | invalid request body, missing required fields, or invalid blinded_message hex/point |
| `401 Unauthorized` | missing or malformed Authorization header, or invalid JWT token |
| `500 Internal Server Error` | key derivation failure, DLEQ proof generation failure, or internal server error |

---

### `POST /v1/credential/consume`

Consume a previously issued credential and check replay protection.

- **Authentication:** not required (but rate‑limited)
- **Request Content-Type:** `application/json`

#### Request body

```json
{
  "unblinded_signature": "<hex-encoded compressed G1 point>",
  "witness": "<hex-encoded compressed G1 point>",
  "credential_class": "<credential class>",
  "key_epoch": "<epoch>"
}
```

Fields:
- `unblinded_signature`: client‑side unblinded BLS signature (σ).
- `witness`: the original message point `H(msg)` in G1.
- `credential_class`: same class used during issuance.
- `key_epoch`: epoch returned by issuance (must match).

#### Success response (200)

```json
{
  "valid": true
}
```

#### Failure response (409 Conflict)

```json
{
  "valid": false,
  "error": "credential already redeemed"
}
```

#### Other error responses

| Status | Description |
|--------|-------------|
| `400 Bad Request` | unsupported key_epoch, invalid signature, invalid witness, or missing required fields |
| `500 Internal Server Error` | nullifier store failure or server configuration error |

---

### `POST /v1/admin/revoke`

Revoke a credential class (optionally limited to a specific epoch).  
All future redemptions for that class (or class+epoch) will be rejected until the revocation is lifted.

- **Authentication:** required, JWT must contain the claim `"admin": true`
- **Request Content-Type:** `application/json`

#### Request body

```json
{
  "credential_class": "<class>",
  "key_epoch": "<epoch>",           // optional; if omitted, revokes all epochs
  "reason": "<revocation reason>",
  "revoked_until": "<ISO 8601 timestamp>" // optional; if set, revocation expires at that time
}
```

Fields:
- `credential_class`: (required) the class to revoke.
- `key_epoch`: (optional) restrict revocation to a specific epoch. If omitted, the revocation applies to all epochs for that class.
- `reason`: (required) human‑readable reason for the revocation (logged for audit).
- `revoked_until`: (optional) UTC timestamp (RFC 3339) after which the revocation automatically expires. If omitted, the revocation is permanent until manually unrevoked.

#### Success response (200)

```json
{
  "status": "revoked"
}
```

#### Error responses

| Status | Description |
|--------|-------------|
| `400 Bad Request` | missing required fields (credential_class or reason) |
| `401 Unauthorized` | missing or invalid JWT |
| `403 Forbidden` | JWT does not contain `admin: true` claim |
| `500 Internal Server Error` | storage failure |

---

### `DELETE /v1/admin/revoke`

Remove an active revocation, allowing credentials of that class/epoch to be redeemed again.

- **Authentication:** required, JWT must contain `"admin": true`
- **Request Content-Type:** `application/json`

#### Request body

```json
{
  "credential_class": "<class>",
  "key_epoch": "<epoch>"   // optional; if omitted, removes class‑wide revocation
}
```

Fields:
- `credential_class`: (required) the class to unrevoke.
- `key_epoch`: (optional) if provided, removes the revocation for that specific epoch only; otherwise removes the class‑wide revocation.

#### Success response (200)

```json
{
  "status": "unrevoked"
}
```

#### Error responses

| Status | Description |
|--------|-------------|
| `400 Bad Request` | missing credential_class |
| `401 Unauthorized` | missing or invalid JWT |
| `403 Forbidden` | JWT does not contain `admin: true` claim |
| `500 Internal Server Error` | storage failure |

---

### `GET /v1/admin/revocations`

List all currently active revocations (including permanent and time‑limited ones).

- **Authentication:** required, JWT must contain `"admin": true`
- **Request Content-Type:** (none)

#### Success response (200)

```json
{
  "revocations": [
    {
      "credential_class": "airdrop_2026",
      "key_epoch": "2026-01",
      "reason": "vulnerability detected",
      "revoked_at": "2026-07-28T10:00:00Z",
      "revoked_until": "2026-08-01T10:00:00Z",
      "revoked_by": "admin@example.com"
    },
    {
      "credential_class": "faucet",
      "key_epoch": "",    // empty means all epochs
      "reason": "deprecated",
      "revoked_at": "2026-07-20T08:00:00Z",
      "revoked_until": null,
      "revoked_by": "admin@example.com"
    }
  ]
}
```

Fields:
- `credential_class`: the revoked class.
- `key_epoch`: the epoch, or empty string if class‑wide.
- `reason`: the provided reason.
- `revoked_at`: when the revocation was created (UTC).
- `revoked_until`: when the revocation expires (if set), otherwise `null`.
- `revoked_by`: the admin identity (subject from JWT).

#### Error responses

| Status | Description |
|--------|-------------|
| `401 Unauthorized` | missing or invalid JWT |
| `403 Forbidden` | JWT does not contain `admin: true` claim |
| `500 Internal Server Error` | storage failure |

---

### `GET /health`

Returns basic health status.

#### Success response (200)

```json
{
  "status": "ok"
}
```

---

## Error response format

All error responses (except those coming from middleware) use the same JSON envelope:

```json
{
  "error": "<human-readable message>",
  "code": <HTTP status code>,
  "details": "<optional extra information>"
}
```

---

## Notes

- `credential_class` and `key_epoch` must match between issuance and consumption.
- `POST /v1/credential/issue` requires JWT authentication; the admin endpoints require an additional `admin: true` claim.
- `POST /v1/credential/consume` does **not** require authentication, but is subject to per‑IP rate limiting (configurable).
- The service applies rate limiting to **all** request handlers to prevent abuse.
- Revocation entries with a `revoked_until` field automatically expire and no longer block redemptions after that time.
- For production deployments, ensure the master seed and auth secret are stored securely (e.g., using a secrets manager).