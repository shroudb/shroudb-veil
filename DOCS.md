# ShrouDB Veil Documentation

ShrouDB Veil enables **encrypted search over end-to-end encrypted data**. It decrypts ciphertexts via a Transit engine, matches queries against the plaintext in memory, and returns only match metadata — plaintext never leaves the process and is securely erased after each operation.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Operational Modes](#operational-modes)
- [Configuration](#configuration)
- [Search Commands](#search-commands)
- [Indexing](#indexing)
- [Token Pre-filtering](#token-pre-filtering)
- [Admin Commands](#admin-commands)
- [Security Model](#security-model)
- [Client Libraries](#client-libraries)
- [Deployment](#deployment)

---

## Quick Start

### Build from source

```bash
cargo build --release
```

To build a smaller binary without the embedded Transit engine (remote mode only):

```bash
cargo build --release --no-default-features
```

### Run in embedded mode

Embedded mode runs a Transit crypto engine in-process. No external dependencies are required — just provide a master key.

```bash
export SHROUDB_MASTER_KEY="$(openssl rand -base64 32)"
./target/release/shroudb-veil
```

### Run in remote mode

Remote mode delegates all cryptographic operations to an external Transit server.

```bash
./target/release/shroudb-veil --transit transit.internal:6499
```

Veil listens on **TCP port 6599** by default.

---

## Operational Modes

| Mode | Description | State | Requirements |
|------|-------------|-------|--------------|
| **Embedded** | Transit engine runs in-process. Single binary, no external dependencies. | Persistent (WAL + snapshots) | `SHROUDB_MASTER_KEY` or `SHROUDB_MASTER_KEY_FILE` |
| **Remote** | Proxies crypto operations to an external Transit server over TCP. | Stateless | Reachable Transit server |

Set `transit.addr` in the config file or pass `--transit <addr>` to activate remote mode. When neither is set, Veil defaults to embedded mode.

---

## Configuration

Veil reads a TOML config file (default: `veil.toml`). Override the path with `--config <path>`.

Environment variables can be interpolated using `${VAR_NAME}` syntax.

### Server

```toml
[server]
bind = "0.0.0.0:6599"          # TCP listen address
tls_cert = "path/to/cert.pem"  # TLS certificate (optional)
tls_key = "path/to/key.pem"    # TLS private key (optional)
tls_client_ca = "path/to/ca.pem"  # mTLS client CA (optional)
rate_limit = null               # Max requests/sec (optional)
```

### Transit (remote mode)

```toml
[transit]
addr = "transit.internal:6499" # Transit server address (activates remote mode)
tls = false                    # Use TLS for Transit connection
token = null                   # Auth token (optional)
pool_size = 4                  # Connection pool size
```

### Search

```toml
[search]
max_batch_size = 50000         # Max ciphertexts per request
default_result_limit = 100     # Default LIMIT if not specified
decrypt_batch_size = 500       # Ciphertexts decrypted per batch
```

### Keyrings (embedded mode)

Keyrings define encryption keys and their lifecycle.

```toml
[keyrings.messages]
algorithm = "aes-256-gcm"     # aes-256-gcm | chacha20-poly1305
rotation_days = 90             # Rotate active key every N days
drain_days = 30                # Keep old key for decryption N days after rotation
convergent = false             # Must be false for data keyrings

[keyrings."messages:tokens"]
algorithm = "aes-256-gcm"
convergent = true              # Must be true for token keyrings
```

A **token keyring** uses convergent (deterministic) encryption so that identical plaintext always produces the same ciphertext. This is required for token pre-filtering. Token keyrings are named `<data-keyring>:tokens` by convention.

### Storage (embedded mode)

```toml
[storage]
data_dir = "./veil-data"                # WAL and snapshot directory
wal_fsync_mode = "batched"              # per_write | batched | periodic
wal_fsync_interval_ms = 10              # Fsync interval (batched/periodic)
wal_segment_max_bytes = 67108864        # 64 MB segment size
snapshot_interval_entries = 100000      # Snapshot every N entries
snapshot_interval_minutes = 60          # Snapshot every N minutes
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `SHROUDB_MASTER_KEY` | Base64-encoded 32-byte master key (embedded mode) |
| `SHROUDB_MASTER_KEY_FILE` | Path to a file containing the master key |
| `LOG_LEVEL` | Logging verbosity: `debug`, `info` (default), `warn` |

### CLI Flags

| Flag | Description |
|------|-------------|
| `--config <path>` | Config file path (default: `veil.toml`) |
| `--transit <addr>` | Override Transit address (forces remote mode) |

---

## Search Commands

All search commands share the same structure:

```
<MODE> <keyring> QUERY <query> [FIELD <field>] [CONTEXT <aad>] [LIMIT <n>] [REWRAP] CIPHERTEXTS <ct1> <ct2> ...
```

Or with pre-computed tokens:

```
<MODE> <keyring> QUERY <query> [FIELD <field>] [CONTEXT <aad>] [LIMIT <n>] [REWRAP] ENTRIES <base64_json>
```

### Match Modes

| Command | Behavior | Example |
|---------|----------|---------|
| `EXACT` | Case-insensitive exact equality | `EXACT users QUERY "alice"` |
| `CONTAINS` | Case-insensitive substring match | `CONTAINS messages QUERY "dinner"` |
| `PREFIX` | Word-boundary prefix match | `PREFIX contacts QUERY "al"` |
| `FUZZY` | Levenshtein distance ≤ 2 (typo-tolerant) | `FUZZY messages QUERY "dinnar"` |

### Options

| Option | Description |
|--------|-------------|
| `FIELD <name>` | Search a specific JSON field in the decrypted payload (default: full text) |
| `CONTEXT <aad>` | Additional authenticated data passed to Transit for decryption |
| `LIMIT <n>` | Maximum results to return (default: `search.default_result_limit`) |
| `REWRAP` | Re-encrypt matching ciphertexts under the current active key version |

### Response Format

```json
{
  "status": "OK",
  "scanned": 200,
  "matched": 3,
  "filtered": 4800,
  "results": [
    {
      "id": "0",
      "score": 0.987
    }
  ]
}
```

| Field | Description |
|-------|-------------|
| `scanned` | Entries decrypted and checked |
| `matched` | Total matches (before LIMIT truncation) |
| `filtered` | Entries excluded by token pre-filter (not decrypted) |
| `results[].id` | Index of the matching ciphertext in the input |
| `results[].score` | Relevance score (0.0–1.0), sorted descending |
| `results[].ciphertext` | Present only when `REWRAP` is used |
| `results[].key_version` | Present only when `REWRAP` is used |

### Scoring

- **Exact**: always 1.0
- **Contains / Prefix / Fuzzy**: `query_length / text_length`, capped at 1.0
- Results are returned sorted by descending score

---

## Indexing

The `INDEX` command encrypts plaintext and generates search tokens in a single call:

```
INDEX <keyring> <base64_plaintext> [FIELD <field>] [CONTEXT <aad>]
```

**Response:**

```json
{
  "status": "OK",
  "ciphertext": "v1:gcm:...",
  "tokens": ["v1:gcm:t1", "v1:gcm:t2", "..."]
}
```

Store both the `ciphertext` and `tokens` alongside your records. The tokens enable efficient pre-filtering at search time (see below).

### How Tokenization Works

Given a plaintext value, Veil generates two kinds of tokens:

- **Word tokens** — each normalized (lowercased) word, e.g. `"dinner"` → `w:dinner`
- **Trigram tokens** — overlapping 3-character sequences, e.g. `"dinner"` → `t:din`, `t:inn`, `t:nne`, `t:ner`

All tokens are encrypted with the keyring's convergent token keyring before being returned.

---

## Token Pre-filtering

For large datasets, decrypting every ciphertext to check for matches is expensive. Token pre-filtering avoids this by comparing encrypted tokens **before** decryption.

### Workflow

1. **At write time**: call `INDEX` to produce a ciphertext and encrypted tokens. Store both.
2. **At search time**: pass entries with their tokens using the `ENTRIES` keyword instead of `CIPHERTEXTS`:

```
CONTAINS messages QUERY "dinner" ENTRIES <base64_json>
```

Where `<base64_json>` decodes to:

```json
[
  {"ct": "<ciphertext>", "tokens": ["<token1>", "<token2>", "..."]},
  {"ct": "<ciphertext>", "tokens": ["<token1>", "<token2>", "..."]}
]
```

Veil encrypts the query's tokens with the same convergent keyring and compares them against each entry's token set. Only entries with matching tokens are decrypted and searched — dramatically reducing the number of decrypt operations.

The `filtered` field in the response shows how many entries were skipped by this optimization.

---

## Admin Commands

| Command | Description |
|---------|-------------|
| `HEALTH` | Returns server and Transit engine health status |
| `CONFIG GET <key>` | Read a runtime config value |
| `CONFIG SET <key> <value>` | Set a runtime config value (in-memory only, not persisted) |
| `CONFIG LIST` | List all config keys and values |

---

## Security Model

### Plaintext Protection

- Plaintext exists only in process memory during query execution
- All plaintext buffers are **zeroized on drop** — securely erased after use
- Core dumps are disabled at startup to prevent memory leaks via crash artifacts
- Plaintext is **never** stored, logged, or returned to clients

### Key Isolation

- **Embedded mode**: The master key encrypts all key material at rest (WAL and snapshots). The master key itself is provided via environment variable and never written to disk by Veil.
- **Remote mode**: Veil never handles key material. All cryptographic operations are delegated to the external Transit server.

### Network Security

- Optional TLS for client connections (cert + key)
- Optional mTLS for mutual authentication (client CA)
- Optional TLS for Transit connections (remote mode)
- Optional auth token for Transit connections
- Optional rate limiting

### Audit Logging

All commands (except `HEALTH`) are logged to the `veil::audit` log target, including the operation type, keyring, result status, and duration.

---

## Client Libraries

### Rust Client

The `shroudb-veil-client` crate provides a typed async client:

```rust
use shroudb_veil_client::VeilClient;

let client = VeilClient::connect("127.0.0.1:6599").await?;

// Search
let results = client
    .contains("messages", "dinner")
    .field("body")
    .limit(10)
    .ciphertexts(&ciphertexts)
    .execute()
    .await?;

// Index
let indexed = client
    .index("messages", plaintext_b64)
    .field("body")
    .execute()
    .await?;
```

### CLI

The `shroudb-veil-cli` binary provides an interactive REPL for manual testing:

```bash
shroudb-veil-cli --addr 127.0.0.1:6599
# or
shroudb-veil-cli --uri shroudb-veil://token@host:6599
```

Use `--json` for machine-readable output. Type `help` at the prompt for available commands.

---

## Deployment

### Docker

```bash
# Embedded mode (ephemeral — data lost on restart)
docker run -p 6599:6599 shroudb/veil

# Embedded mode (persistent)
docker run -d \
  -p 6599:6599 \
  -v veil-data:/data \
  -v ./veil.toml:/veil.toml:ro \
  -e SHROUDB_MASTER_KEY="$(openssl rand -base64 32)" \
  shroudb/veil --config /veil.toml

# Remote mode
docker run -d \
  -p 6599:6599 \
  shroudb/veil --transit transit.internal:6499
```

### Docker Compose

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

### Production Recommendations

- **Always use TLS** for both client and Transit connections in production
- **Persist the master key** securely (e.g., a secrets manager). Losing it means losing access to all encrypted data in embedded mode.
- **Mount a persistent volume** at the configured `data_dir` for embedded mode to survive restarts
- **Set `wal_fsync_mode = "per_write"`** for maximum durability in embedded mode, at the cost of write throughput
- **Use token pre-filtering** for datasets larger than a few thousand entries to minimize decrypt operations
- **Set a rate limit** (`server.rate_limit`) to protect against abuse
- **Enable mTLS** (`tls_client_ca`) when Veil is exposed beyond a private network
