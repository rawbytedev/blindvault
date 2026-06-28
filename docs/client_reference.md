# Client Reference

BlindVault ships with a Go client library in `pkg/client` and a command-line interface in `cmd/bv`.

## Go client package

### Import

```go
import "blindvault/pkg/client"
```

### Create a client

```go
cli, err := client.NewClient(&client.Config{
    ServerURL: "http://localhost:8080",
    DST:       []byte("BCIS-V1-MESSAGE"),
})
if err != nil {
    // handle error
}
```

### Blind a message

```go
result, err := cli.Blind([]byte("hello world"))
```

Returns a `*client.BlindResult` with:
- `Blinded`: the blinded G1 point sent to the server
- `Witness`: the original hashed message point
- `RequestID`: local request identifier used for later unblinding

The client stores blinding state in `~/.blindvault/state.json`.

### Verify a DLEQ proof

```go
valid := cli.VerifyProof(proof, blindedPoint, signaturePoint, publicKeyPoint)
```

This verifies a server-provided DLEQ proof for a blinded signature without contacting the server.

### Unblind a blind signature

```go
unblinded, err := cli.Unblind(requestID, blindSignature)
```

The client looks up the saved blinding scalar for `requestID`, unblinds the signature, and removes the pending request from local state.

### Redeem a credential

```go
valid, err := cli.Redeem(unblindedSignature, witness, "tier_gold", "2026-01")
```

This sends a `POST /v1/credential/consume` request to the server and returns whether the credential was accepted.

## CLI usage

The CLI is implemented in `cmd/bv`.

### Build

```bash
go build -o bv ./cmd/bv
```

### Commands

#### blind

Issue a blinded credential request and store the blinding state locally.

Flags:
- `--message` (required): plaintext message to blind
- `--dst`: domain separation tag (default: `BCIS-V1-MESSAGE`)
- `--server`: BlindVault server URL (default: `http://localhost:8080`)

Example:

```bash
bv blind --message "user@example.com"
```

Output:

```json
{
  "blinded": "<hex>",
  "witness": "<hex>",
  "request_id": "<id>"
}
```

#### verify

Verify a server-provided DLEQ proof locally.

Flags:
- `--blinded` (required)
- `--signature` (required)
- `--public-key` (required)
- `--proof-r1` (required)
- `--proof-r2` (required)
- `--proof-s` (required)
- `--proof-c` (required)
- `--dst`: domain separation tag (default: `BCIS-V1-MESSAGE`)
- `--server`: BlindVault server URL (default: `http://localhost:8080`)

Example:

```bash
bv verify --blinded <hex> --signature <hex> --public-key <hex> --proof-r1 <hex> --proof-r2 <hex> --proof-s <hex> --proof-c <hex>
```

#### unblind

Unblind a blind signature using a stored request ID.

Flags:
- `--signature` (required)
- `--id` (required)
- `--dst`: domain separation tag (default: `BCIS-V1-MESSAGE`)
- `--server`: BlindVault server URL (default: `http://localhost:8080`)

Example:

```bash
bv unblind --signature <blind_signature_hex> --id <request_id>
```

Output:

```text
Unblinded signature: <hex>
```

#### redeem

Redeem an unblinded credential against the server.

Flags:
- `--signature` (required)
- `--witness` (required)
- `--class` (required)
- `--epoch` (required)
- `--dst`: domain separation tag (default: `BCIS-V1-MESSAGE`)
- `--server`: BlindVault server URL (default: `http://localhost:8080`)

Example:

```bash
bv redeem --signature <unblinded_signature_hex> --witness <witness_hex> --class tier_gold --epoch 2026-01
```

Output on success:

```text
Credential redeemed successfully
```

## Local state

The CLI stores pending blind session state in `~/.blindvault/state.json` so `unblind` can recover the blinding scalar for a prior `blind` request.
