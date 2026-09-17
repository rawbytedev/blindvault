# BlindVault

<p align="center">
  <a href="https://github.com/rawbytedev/blindvault/actions/workflows/ci.yml">
    <img src="https://github.com/rawbytedev/blindvault/actions/workflows/ci.yml/badge.svg" alt="CI" />
  </a>
  <a href="https://goreportcard.com/report/github.com/rawbytedev/blindvault">
    <img src="https://goreportcard.com/badge/github.com/rawbytedev/blindvault" alt="Go Report Card" />
  </a>
  <a href="https://github.com/rawbytedev/blindvault">
    <img src="https://img.shields.io/github/go-mod/go-version/rawbytedev/blindvault" alt="Go Version" />
  </a>
  <a href="https://github.com/rawbytedev/blindvault">
    <img src="https://img.shields.io/github/last-commit/rawbytedev/blindvault" alt="GitHub last commit" />
  </a>
  <a href="https://github.com/rawbytedev/blindvault/releases/latest">
    <img src="https://img.shields.io/github/v/release/rawbytedev/blindvault" alt="GitHub Release" />
  </a>
  <a href="https://github.com/rawbytedev/blindvault/issues">
    <img src="https://img.shields.io/github/issues/rawbytedev/blindvault" alt="GitHub issues" />
  </a>
</p>

BlindVault is a privacy-preserving credential issuance and redemption service built on BLS12-381 blind signatures and DLEQ proofs.

## Purpose

BlindVault enables clients to request unbiased blind credentials, verify that the server signed them with a derived public key, and consume them without revealing the underlying secret material.

## Features

- Blind credential issuance using BLS12-381 blind signatures
- DLEQ proof of correct signing key usage
- Epoch and credential class key derivation from a single master seed
- Replay protection using deterministic nullifiers
- Redis-backed nullifier and revocation stores for production
- JWT-protected issuance and admin endpoints
- Health and Prometheus metrics endpoints
- Optional demo endpoints for local testing and examples

## Quickstart

1. Create `configs/config.yaml` or set environment variables.
2. Set a master seed using the preferred environment variables:

```bash
export BLINDVAULT_MASTER_SEED_HEX=<32-byte-hex-seed>
# or, for file-based secret injection:
export BLINDVAULT_SEED_FILE=/path/to/seed.txt
```

3. Run the server:

```bash
go run ./cmd/server/main.go --config configs/config.yaml
```

4. Validate health:

```bash
curl http://localhost:8080/health
```

5. Optional: scrape Prometheus metrics:

```bash
curl http://localhost:8080/metrics
```

## Documentation

- `docs/api_reference.md` — API endpoints, request and response formats, and errors
- `docs/client_reference.md` — Go client library and CLI usage
- `docs/deployment_guide.md` — deployment, Docker Compose, Redis setup, and health checks
- `docs/crypto_spec.md` — cryptographic specification, DLEQ proof details, and security assumptions
- `docs/crypto_vectors.md` — generated test vector placeholder
- `CONTRIBUTING.md` — contribution process and testing guidelines

## Client package and CLI

BlindVault includes a high-level Go client wrapper in `pkg/client` and a command-line interface in `cmd/bv`.

Build the CLI:

```bash
go build -o bv ./cmd/bv
```

Examples:

```bash
bv blind --message "hello" --server http://localhost:8080
bv unblind --signature <blind_signature_hex> --id <request_id>
bv redeem --signature <unblinded_signature_hex> --witness <witness_hex> --class tier_gold --epoch 2026-01
```

The `blind` command returns JSON with `blinded`, `witness`, and `request_id`. The `verify` command validates a DLEQ proof locally, `unblind` converts a blind signature into an unblinded one using the stored request state, and `redeem` submits the credential to `/v1/credential/consume`.

Client state is persisted to `~/.blindvault/state.json`.

## Running tests

```bash
go test ./...
go test -v ./pkg/crypto
```

## Generating crypto vectors

```bash
go run scripts/generate_vectors.go --output docs/crypto_vectors.md
```

## Configuration

The server reads the YAML config and applies environment overrides. The preferred secret-loading paths are:

- `BLINDVAULT_MASTER_SEED_HEX` for in-memory secrets
- `BLINDVAULT_SEED_FILE` for a secret file loaded from disk
- `MASTER_SEED_HEX` is still accepted for compatibility, but the `BLINDVAULT_*` names are the safer and clearer path

Common runtime overrides include:

- `ACTIVE_EPOCH`
- `SUPPORTED_EPOCHS`
- `DST`
- `AUTH_SECRET`
- `REDIS_ADDR`
- `REDIS_PASSWORD`
- `REDIS_DB`
- `REDIS_EXPIRATION`
- `REVOCATION_REDIS_ADDR`
- `REVOCATION_REDIS_DB`
- `USE_MEMORY_STORE`
- `LISTEN_ADDR`
- `RATE_LIMIT_REQUESTS`
- `RATE_LIMIT_BURST`

## Notes

Use `use_memory_store: true` only for testing. Production deployment should use Redis, protect the master seed and JWT secret with a secrets manager, and keep admin authorization separate from application user identity flows.
