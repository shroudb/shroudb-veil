# ShrouDB Veil

Encrypted search over E2EE data — search ciphertexts without exposing keys or plaintext.

## Quick Start

```sh
# Embedded mode (ephemeral master key, data lost on restart)
docker run -p 6599:6599 shroudb/veil

# Production (persistent storage + master key)
docker run -d \
  -p 6599:6599 \
  -v veil-data:/data \
  -v ./veil.toml:/veil.toml:ro \
  -e SHROUDB_MASTER_KEY="$(openssl rand -base64 32)" \
  shroudb/veil --config /veil.toml

# Remote mode (connect to external Transit server)
docker run -d \
  -p 6599:6599 \
  shroudb/veil --transit transit.internal:6499
```

## Ports

| Port | Purpose |
|------|---------|
| `6599` | Veil command protocol |

## Volumes

| Path | Purpose |
|------|---------|
| `/data` | WAL segments, snapshots, and key material (embedded mode) |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SHROUDB_MASTER_KEY` | Yes (embedded) | Base64-encoded 32-byte key. Encrypts all key material at rest. |
| `SHROUDB_MASTER_KEY_FILE` | Alternative | Path to a file containing the master key. |
| `LOG_LEVEL` | No | `info`, `debug`, `warn`. Default: `info`. |

In remote mode (`--transit <addr>`), no master key is needed — the external Transit server manages key material.

## Docker Compose

```yaml
services:
  veil:
    image: shroudb/veil
    ports:
      - "6599:6599"
    environment:
      - SHROUDB_MASTER_KEY=${SHROUDB_MASTER_KEY}
    volumes:
      - veil-data:/data
      - ./veil.toml:/veil.toml:ro
    command: ["--config", "/veil.toml"]
    restart: unless-stopped

volumes:
  veil-data:
```

## CLI

A command-line client is available as a separate image:

```sh
docker run --rm -it shroudb/veil-cli --addr host.docker.internal:6599
```

## Image Details

- **Base image:** Alpine 3.21
- **User:** `shroudb` (UID 65532)
- **Architectures:** `linux/amd64`, `linux/arm64`
- **License:** MIT OR Apache-2.0

## Links

- [GitHub](https://github.com/shroudb/shroudb-veil)
- [Documentation](https://github.com/shroudb/shroudb-veil/blob/main/README.md)
- [Homebrew](https://github.com/shroudb/homebrew-tap) — `brew install shroudb/tap/shroudb-veil`
