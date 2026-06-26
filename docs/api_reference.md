# API Reference

## Endpoints

### `POST /v1/credential/issue`

Issue a blind credential and receive a blind signature with proof.

- Authentication: required via `Authorization: Bearer <token>`
- Request Content-Type: `application/json`

#### Request body

```json
{
  "blinded_message": "<hex-encoded compressed G1 point>",
  "credential_class": "<credential class>"
}
```

Fields:
- `blinded_message`: hex-encoded compressed G1 point created by client blinding.
- `credential_class`: application namespace used for key derivation.

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

`400 Bad Request`
- invalid request body
- missing required fields
- invalid blinded_message hex or point

`401 Unauthorized`
- missing or malformed Authorization header
- invalid JWT token

`500 Internal Server Error`
- key derivation failure
- DLEQ proof generation failure
- configuration or internal server error

---

### `POST /v1/credential/consume`

Consume a previously issued credential and check replay protection.

- Authentication: not required by current implementation
- Request Content-Type: `application/json`

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
- `unblinded_signature`: the client-side unblinded BLS signature.
- `witness`: the original message point `H(msg)` in G1.
- `credential_class`: same class used during issuance.
- `key_epoch`: epoch returned by issuance.

#### Success response (200)

```json
{
  "valid": true
}
```

#### Failure response (409)

```json
{
  "valid": false,
  "error": "credential already redeemed"
}
```

#### Other error responses

`400 Bad Request`
- unsupported key_epoch
- invalid signature
- invalid witness
- missing required fields

`500 Internal Server Error`
- nullifier store failure
- server configuration error

---

### `GET /health`

Returns basic health status.

#### Success response (200)

```json
{
  "status": "ok"
}
```

## Error response format

All error responses use the same JSON envelope:

```json
{
  "error": "<message>",
  "code": <status code>,
  "details": "<optional details>"
}
```

## Notes

- `credential_class` and `key_epoch` must match between issuance and consumption.
- `POST /v1/credential/issue` is protected by JWT authentication.
- `POST /v1/credential/consume` currently uses only rate limiting and replay protection.
- The service applies per-IP rate limiting to all request handlers.
