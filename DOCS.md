# ShrouDB Veil Documentation

Encrypted search over E2EE data. ShrouDB Veil decrypts ciphertexts via ShrouDB Transit, matches queries against the plaintext in memory, and returns results — plaintext never leaves the process and is zeroized on drop.

---

## Installation

### Homebrew

```sh
brew install shroudb/tap/shroudb-veil
```

Installs both `shroudb-veil` (server) and `shroudb-veil-cli`.

### Docker

```sh
docker pull shroudb/veil
docker pull shroudb/veil-cli
```

### Binary

Download prebuilt binaries from [GitHub Releases](https://github.com/shroudb/shroudb-veil/releases). Available for Linux (x86_64, aarch64) and macOS (x86_64, Apple Silicon).

---

## Quick Start

**1. Start the server:**

```bash
# Dev mode (ephemeral master key — data won't survive restart)
shroudb-veil --config veil.toml

# Production (persistent master key)
export SHROUDB_MASTER_KEY="base64-encoded-32-byte-key"
shroudb-veil --config veil.toml
```

Default port: `6599`.

**2. Connect with the CLI:**

```bash
shroudb-veil-cli --addr 127.0.0.1:6599
```

Or using a connection URI:

```bash
shroudb-veil-cli --uri shroudb-veil://127.0.0.1:6599
```

**3. Index data (encrypt + tokenize):**

```
> INDEX messages SGVsbG8gV29ybGQ= FIELD body CONTEXT chan-42
{status: OK, ciphertext: "v1:gcm:aGVsbG8...", key_version: 1, tokens: ["KxPq:...", "MnRs:...", ...]}
```

Store the returned `ciphertext` and `tokens` in your database.

**4. Search:**

```
> CONTAINS messages QUERY "hello" CIPHERTEXTS v1:gcm:aGVsbG8... v1:gcm:eHl6...
{status: OK, scanned: 2, matched: 1, filtered: 0, results: [{id: "entry-0", score: 1.0}]}
```

---

## Connection String

URI format:

```
shroudb-veil://[token@]host[:port]
shroudb-veil+tls://[token@]host[:port]
```

Examples:

```
shroudb-veil://127.0.0.1:6599
shroudb-veil://app-token@veil.internal:6599
shroudb-veil+tls://admin-token@veil.prod.example.com:6599
```

---

## Configuration

ShrouDB Veil is configured via a TOML file. Pass it with `--config`:

```bash
shroudb-veil --config veil.toml
```

### Minimal Configuration

```toml
[server]
bind = "0.0.0.0:6599"

[keyrings.messages]
algorithm = "aes-256-gcm"
rotation_days = 90

[keyrings."messages:tokens"]
algorithm = "aes-256-gcm"
convergent = true

[storage]
data_dir = "./veil-data"
```

### Full Configuration Reference

```toml
[server]
bind = "0.0.0.0:6599"
# tls_cert = "/path/to/cert.pem"
# tls_key = "/path/to/key.pem"
# tls_client_ca = "/path/to/ca.pem"  # enables mTLS

[search]
max_batch_size = 50000           # max ciphertexts per query
default_result_limit = 100       # default LIMIT value

# Embedded mode (default): configure keyrings and storage directly.
[keyrings.messages]
algorithm = "aes-256-gcm"
rotation_days = 90
drain_days = 30

[keyrings."messages:tokens"]
algorithm = "aes-256-gcm"
convergent = true                # required for token keyrings

[storage]
data_dir = "./veil-data"

# Remote mode: set transit.addr to proxy crypto to an external Transit server.
# [transit]
# addr = "transit.internal:6499"
# tls = true
# token = "veil-service-token"
# pool_size = 8
```

### Master Key

The master key encrypts all key material at rest (embedded mode). Provide it via environment variable:

- `SHROUDB_MASTER_KEY` — base64-encoded 32-byte key
- `SHROUDB_MASTER_KEY_FILE` — path to a file containing the key

If neither is set, the server starts in dev mode with an ephemeral key. Data will not survive a restart.

### Transit Connection (Remote Mode)

When the `[transit]` section includes an `addr`, Veil operates in remote mode — all cryptographic operations are proxied to an external ShrouDB Transit server. Veil becomes a stateless search frontend.

| Key | Description |
|-----|-------------|
| `addr` | Transit server address (`host:port`) |
| `tls` | Enable TLS for Transit connection |
| `token` | Authentication token for Transit |
| `pool_size` | Connection pool size |

### Search Tuning

Runtime-adjustable via the `CONFIG` command:

| Key | Default | Description |
|-----|---------|-------------|
| `search.max_batch_size` | 50000 | Maximum ciphertexts accepted per query |
| `search.default_result_limit` | 100 | Default LIMIT when not specified |

---

## Commands Reference

### Search Commands

#### CONTAINS

```
CONTAINS <keyring> QUERY <q> [options] CIPHERTEXTS <ct1> <ct2> ...
```

Substring match (case-insensitive). Score is proportional to the ratio of query length to matched text length.

#### EXACT

```
EXACT <keyring> QUERY <q> [options] CIPHERTEXTS <ct1> <ct2> ...
```

Exact equality (case-insensitive). Score is `1.0` on match.

#### PREFIX

```
PREFIX <keyring> QUERY <q> [options] CIPHERTEXTS <ct1> <ct2> ...
```

Word-boundary prefix match. Score is proportional to the ratio of query length to word length.

#### FUZZY

```
FUZZY <keyring> QUERY <q> [options] CIPHERTEXTS <ct1> <ct2> ...
```

Levenshtein distance (up to 2), typo-tolerant. Score decreases with edit distance.

#### Search Options

| Option | Description |
|--------|-------------|
| `FIELD <name>` | Search a specific JSON field (default: all text) |
| `CONTEXT <aad>` | Additional Authenticated Data for decryption |
| `LIMIT <n>` | Maximum results (default: 100) |
| `REWRAP` | Re-encrypt matched entries under the active key |
| `ENTRIES <base64_json>` | Entries with pre-computed tokens: `[{"ct":"...","tokens":[...]}, ...]` |

#### Search Response

```json
{
  "status": "OK",
  "scanned": 200,
  "matched": 3,
  "filtered": 4800,
  "results": [
    { "id": "entry-0", "score": 1.0, "ciphertext": "v4:gcm:...", "key_version": 4 },
    { "id": "entry-1", "score": 0.857 },
    { "id": "entry-2", "score": 0.714 }
  ]
}
```

- `scanned` — entries that passed token filter and were decrypted
- `filtered` — entries skipped by token filter (never decrypted)
- `matched` — entries that matched the query (before LIMIT)
- `ciphertext` and `key_version` — only present if REWRAP was requested

### Indexing

#### INDEX

```
INDEX <keyring> <base64_plaintext> [FIELD <name>] [CONTEXT <aad>]
```

Encrypt plaintext and generate search tokens in one step. Returns the ciphertext, key version, and an array of encrypted search tokens. Store these in your database for later searching.

Tokens are generated by:
1. Splitting text into words and overlapping trigrams
2. Encrypting each token with convergent encryption (deterministic, enabling pre-filtering)

### Administration

#### HEALTH

```
HEALTH
```

Returns server and Transit health status.

#### AUTH

```
AUTH <token>
```

Authenticate the connection when auth is enabled.

#### CONFIG

```
CONFIG GET <key>
CONFIG SET <key> <value>
CONFIG LIST
```

Get, set, or list runtime configuration values. Changes via `CONFIG SET` are in-memory only and do not persist across restarts.

#### PIPELINE

```
PIPELINE
  CONTAINS messages QUERY "hello" CIPHERTEXTS ct1 ct2
  INDEX messages SGVsbG8=
END
```

Batch multiple commands in a single round-trip.

---

## Search Modes

### Exact

Case-insensitive equality. Returns a score of `1.0` when the decrypted value matches the query exactly.

```
> EXACT emails QUERY "alice@example.com" CIPHERTEXTS ct1 ct2 ct3
```

### Contains

Substring search (case-insensitive). Matches any entry containing the query string. Score reflects how much of the text the query covers.

```
> CONTAINS messages QUERY "dinner" FIELD body CIPHERTEXTS ct1 ct2 ct3
```

### Prefix

Word-boundary prefix match. Matches entries where any word starts with the query. Useful for autocomplete-style searches.

```
> PREFIX names QUERY "ali" CIPHERTEXTS ct1 ct2 ct3
```

### Fuzzy

Typo-tolerant search using Levenshtein distance (up to 2 edits). Score decreases with edit distance.

```
> FUZZY names QUERY "alce" CIPHERTEXTS ct1 ct2 ct3
```

This would match "alice" (1 edit distance).

---

## Token Pre-filtering

For large datasets, decrypting every entry on each search is expensive. Token pre-filtering solves this.

**How it works:**

1. At index time, `INDEX` generates encrypted search tokens (word tokens and trigram tokens) alongside the ciphertext.
2. Store the tokens with the ciphertext in your database.
3. At search time, pass tokens alongside ciphertexts using the `ENTRIES` option.
4. Veil compares query tokens against entry tokens and skips entries with zero overlap — without decrypting them.

**Example flow:**

```
# Index: encrypt + generate tokens
> INDEX messages SGVsbG8gd29ybGQ= FIELD body CONTEXT chan-42
{ciphertext: "AbCd:...", tokens: ["KxPq:...", "MnRs:...", ...]}

# Search: pass tokens for pre-filtering
> CONTAINS messages QUERY "hello" ENTRIES eyJjdCI6Ii4uLiIsInRva2VucyI6Wy4uLl19
{scanned: 200, matched: 3, filtered: 4800, results: [...]}
```

In this example, 4800 entries were skipped by token filtering — only 200 needed decryption.

---

## Docker Deployment

The server image (`shroudb/veil`) runs as a non-root user on a minimal Alpine base.

**1. Create a config file** (`veil.toml`):

```toml
[server]
bind = "0.0.0.0:6599"

[storage]
data_dir = "/data"

[keyrings.messages]
algorithm = "aes-256-gcm"
rotation_days = 90
drain_days = 30

[keyrings."messages:tokens"]
algorithm = "aes-256-gcm"
convergent = true
```

**2. Run the server:**

```bash
docker run -d \
  --name shroudb-veil \
  -p 6599:6599 \
  -v veil-data:/data \
  -v ./veil.toml:/veil.toml:ro \
  -e SHROUDB_MASTER_KEY="base64-encoded-32-byte-key" \
  shroudb/veil \
  --config /veil.toml
```

- `-v veil-data:/data` — persists key material and snapshots. **Without this volume, all key material is lost on container restart.**
- `-v ./veil.toml:/veil.toml:ro` — mounts the config file read-only.
- `-e SHROUDB_MASTER_KEY` — the 32-byte base64-encoded master key. Can also use `SHROUDB_MASTER_KEY_FILE` pointing to a mounted secrets file.

**3. Connect with the CLI:**

```bash
docker run --rm -it shroudb/veil-cli --addr <veil-host>:6599
```

---

## Telemetry

ShrouDB Veil exposes operational metrics for monitoring engine health and performance:

- **Command counters** — track search, index, and administrative operations by keyring and outcome.
- **Latency histograms** — measure command execution time for performance monitoring and SLA tracking.
- **Connection tracking** — monitor concurrent client connections.
- **Audit logging** — all search and index operations are logged with keyring, outcome, and duration for compliance and debugging.

Telemetry is built on the `shroudb-telemetry` foundation shared across all ShrouDB engines, supporting console, file, and OpenTelemetry output.
