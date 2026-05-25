# azure-keyvault-emulator

Go-based Azure Key Vault emulator that implements a large subset of the Azure Key Vault REST API (7.4) for secrets, keys, and certificates.

## Features

- Secrets API with versioning, pagination, soft-delete, backup, and restore
- Keys API with RSA, EC, and symmetric keys plus encrypt/decrypt, sign/verify, and wrap/unwrap operations
- Certificates API with self-signed certificate creation, import, policy, soft-delete, and recovery
- No authentication required
- Thread-safe in-memory store
- HTTP and HTTPS listeners with auto-generated self-signed TLS certificate
- Request logging with method, path, status code, and duration

## Run locally

```bash
go run .
```

Environment variables:

- `PORT` (default: `8080`)
- `HTTPS_PORT` (default: `8443`)

The emulator accepts any `api-version` value and uses the request `Host` header to build Key Vault-style IDs. If the host is not a vault hostname, it falls back to `emulator`.

## Docker

```bash
docker compose up --build
```

## Example

```bash
curl -X PUT 'http://localhost:8080/secrets/my-secret?api-version=7.4' \
  -H 'Content-Type: application/json' \
  -d '{"value":"secret-value","contentType":"text/plain","tags":{"env":"dev"}}'
```

## Tests

```bash
go build ./...
go test ./...
```
