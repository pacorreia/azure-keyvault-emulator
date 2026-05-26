# azure-keyvault-emulator

Go-based Azure Key Vault emulator that implements a large subset of the Azure Key Vault REST API (7.4) for secrets, keys, and certificates.

## Features

- Secrets API with versioning, pagination, soft-delete, backup, and restore
- Keys API with RSA, EC, and symmetric keys plus encrypt/decrypt, sign/verify, and wrap/unwrap operations
- Certificates API with self-signed certificate creation, import, policy, soft-delete, and recovery
- Pluggable storage backends: memory, SQLite, PostgreSQL, and SQL Server
- No authentication required
- HTTP and HTTPS listeners with auto-generated self-signed TLS certificate
- `/healthz` endpoint for probes
- Request logging with method, path, status code, and duration

## Run locally

```bash
go run .
```

## Environment variables

- `PORT` (default: `8080`)
- `HTTPS_PORT` (default: `8443`)
- `STORE_BACKEND` (default: `memory`) — `memory`, `sqlite`, `postgres`, `mssql`
- `STORE_DSN` — required for `postgres` and `mssql`; defaults to `keyvault.db` for `sqlite`

The emulator accepts any `api-version` value and uses the request `Host` header to build Key Vault-style IDs. If the host is not a vault hostname, it falls back to `emulator`.

## Database backends

### Memory

```bash
STORE_BACKEND=memory go run .
```

### SQLite

```bash
STORE_BACKEND=sqlite STORE_DSN=keyvault.db go run .
```

For tests or ephemeral runs you can use `STORE_DSN=:memory:`.

### PostgreSQL

```bash
STORE_BACKEND=postgres STORE_DSN='postgres://keyvault:keyvault@localhost:5432/keyvault?sslmode=disable' go run .
```

### SQL Server

```bash
STORE_BACKEND=mssql STORE_DSN='sqlserver://sa:Your_password123@localhost:1433?database=keyvault' go run .
```

## Docker

```bash
docker compose up --build
```

Container image:

```bash
docker pull ghcr.io/pacorreia/azure-keyvault-emulator:latest
```

## Helm chart

The repository includes a chart at `charts/azure-keyvault-emulator`.

```bash
helm install keyvault-emulator ./charts/azure-keyvault-emulator
```

Example SQLite persistence:

```bash
helm install keyvault-emulator ./charts/azure-keyvault-emulator \
  --set store.backend=sqlite \
  --set persistence.enabled=true
```

## Releasing

Releases are managed with release-please and conventional commits.

- `feat:` and `fix:` commits drive releases
- `feat!:` is treated as a breaking change
- Release PRs are created from `main`
- Publishing a GitHub Release builds container images and release binaries

## Example

```bash
curl -X PUT 'http://localhost:8080/secrets/my-secret?api-version=7.4' \
  -H 'Content-Type: application/json' \
  -d '{"value":"secret-value","contentType":"text/plain","tags":{"env":"dev"}}'
```

## Tests

```bash
go build ./...
go test ./... -cover
```
