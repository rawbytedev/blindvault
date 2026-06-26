# Contributing to BlindVault

Thanks for helping improve BlindVault. This guide explains the repository workflow, testing, and contribution expectations.

## Getting started

1. Fork the repository.
2. Create a feature branch from `main`.
3. Keep changes small and focused.

## Development workflow

- Use `go test ./...` to run all tests.
- Use `gofmt -w .` before submitting code.
- Add tests for new behavior or bug fixes.

## Running tests

```bash
go test ./...
go test -v ./pkg/crypto
go test -v ./internal/api
```

Generate crypto vectors when updating protocol or test fixtures:

```bash
go run scripts/generate_vectors.go --output docs/crypto_vectors.md
```

## Pull request checklist

- Code is formatted with `gofmt`
- Tests pass locally
- Documentation updated as needed
- No secrets are added to version control
- New endpoint or crypto behavior is documented

## Issue and PR guidelines

- Describe the problem clearly.
- Include steps to reproduce or request details.
- Link related issues if any.

## Code style

- Prefer clear naming and small helper functions.
- Avoid global state when possible.
- Keep crypto operations constant-time where feasible.

## Notes

- `use_memory_store` is only suitable for test or local development.
- The service currently requires JWT auth for credential issuance only.
