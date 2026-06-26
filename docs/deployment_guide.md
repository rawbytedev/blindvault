# Deployment Guide

## Overview

This guide covers deployment options for BlindVault, including environment variables, Redis setup, and health checks.

## Prerequisites

- Go 1.25 or newer
- Redis 7.x (or compatible)
- Optional: Docker and Docker Compose

## Configuration

BlindVault reads from a YAML config file and then applies environment variable overrides.

### Sample `configs/config.yaml`

```yaml
listen_addr: ":8080"
master_seed_hex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
active_epoch: "2026-01"
supported_epochs:
  - "2026-01"
  - "2025-12"
dst: "BCIS-V1-MESSAGE"
auth_secret: "super-secret-token"
redis_addr: "localhost:6379"
redis_password: ""
redis_db: 0
use_memory_store: false
```

### Environment variable overrides

The server will override YAML values when the following environment variables are set:

- `MASTER_SEED_HEX`
- `ACTIVE_EPOCH`
- `REDIS_ADDR`
- `AUTH_SECRET`

Additional config values may be loaded through the service config struct if extended.

## Redis setup

BlindVault uses Redis for nullifier replay protection.

Recommended Redis settings:

- persistence enabled if you want replay history to survive restarts.
- ACL or network restrictions to limit access to the service.

## Running locally

```bash
go run ./cmd/server/main.go --config configs/config.yaml
```

If you need to override values on the command line:

```bash
export MASTER_SEED_HEX=...
export ACTIVE_EPOCH=2026-01
export REDIS_ADDR=localhost:6379
export AUTH_SECRET=super-secret
go run ./cmd/server/main.go --config configs/config.yaml
```

## Docker Compose example

```yaml
version: '3.9'
services:
  redis:
    image: redis:7
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data

  blindvault:
    image: golang:1.25
    working_dir: /app
    volumes:
      - .:/app:delegated
    command: go run ./cmd/server/main.go --config configs/config.yaml
    environment:
      - MASTER_SEED_HEX=${MASTER_SEED_HEX}
      - ACTIVE_EPOCH=${ACTIVE_EPOCH}
      - REDIS_ADDR=redis:6379
      - AUTH_SECRET=${AUTH_SECRET}
    ports:
      - "8080:8080"
    depends_on:
      - redis

volumes:
  redis-data:
```

> Note: For production, build a dedicated runtime image instead of using `golang:1.25`.

## Health checks

The service exposes a basic readiness probe at:

```bash
curl http://localhost:8080/health
```

Expected response:

```json
{ "status": "ok" }
```

## Production recommendations

- Do not use `use_memory_store: true` in production.
- Protect `MASTER_SEED_HEX` and `AUTH_SECRET` with secret management.
- Use Redis ACLs and TLS if available.
- Expose only the required API endpoints through your ingress.
- Monitor logs and request rates, especially issuance traffic.
