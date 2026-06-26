# BlindVault

BlindVault is a privacy-preserving credential issuance and redemption service built on BLS12-381 blind signatures and DLEQ proofs.

## Purpose

BlindVault enables clients to request unbiased blind credentials, verify that the server signed them with a derived public key, and consume them without revealing the underlying secret material.

## Features

- Blind credential issuance using BLS12-381 blind signatures
- DLEQ proof of correct signing key usage
- Epoch and credential class key derivation from a single master seed
- Replay protection using deterministic nullifiers
- Redis-backed nullifier store for production
- JWT-protected issuance endpoint
- Health endpoint for readiness checks

## Quickstart

1. Create `configs/config.yaml` or set environment variables.
2. Run the server:

```bash
go run ./cmd/server/main.go --config configs/config.yaml
```

3. Validate health:

```bash
curl http://localhost:8080/health
```

## Documentation

- `docs/api_reference.md` — API endpoints, request and response formats, and errors
- `docs/deployment_guide.md` — deployment, Docker Compose, Redis setup, and health checks
- `docs/crypto_spec.md` — cryptographic specification, DLEQ proof details, and security assumptions
- `docs/crypto_vectors.md` — generated test vector placeholder
- `CONTRIBUTING.md` — contribution process and testing guidelines

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

You can override config values with environment variables:

- `MASTER_SEED_HEX`
- `ACTIVE_EPOCH`
- `SUPPORTED_EPOCHS`
- `DST`
- `AUTH_SECRET`
- `REDIS_ADDR`
- `REDIS_PASSWORD`
- `REDIS_DB`
- `USE_MEMORY_STORE`
- `LISTEN_ADDR`

## Notes

Use `use_memory_store: true` only for testing. Production deployment should use Redis and protect `MASTER_SEED_HEX` and `AUTH_SECRET` with a secrets manager.
