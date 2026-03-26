# ShrouDB Veil

Encrypted search over E2EE data. Veil decrypts ciphertexts via [ShrouDB Transit](https://github.com/shroudb/shroudb-transit), matches queries against the plaintext in memory, and returns results — plaintext never leaves the process and is zeroized on drop.

## How it works

```
Client                         Veil                          Transit
  │                              │                              │
  │  CONTAINS messages           │                              │
  │  QUERY "dinner"              │                              │
  │  CIPHERTEXTS ct1 ct2 ct3     │                              │
  │─────────────────────────────>│                              │
  │                              │  PIPELINE DECRYPT ct1 ct2 ct3│
  │                              │─────────────────────────────>│
  │                              │  [plaintext1, plaintext2, …] │
  │                              │<─────────────────────────────│
  │                              │                              │
  │                              │  match("dinner", plaintext)  │
  │                              │  zeroize(plaintext)           │
  │                              │                              │
  │  { matched: 1, results: … } │                              │
  │<─────────────────────────────│                              │
```

## Modes

**Embedded** (default) — runs Transit's engine in-process. Single binary, no external dependencies. Decrypt/encrypt operations are direct function calls with zero serialization overhead.

**Remote** — proxies cryptographic operations to an external Transit server over TCP. Veil is a stateless search frontend; Transit manages all key material.

## Search commands

| Command | Description |
|---------|-------------|
| `FUZZY <keyring> QUERY <q> CIPHERTEXTS <ct> ...` | Levenshtein distance, typo-tolerant |
| `CONTAINS <keyring> QUERY <q> CIPHERTEXTS <ct> ...` | Substring match (case-insensitive) |
| `EXACT <keyring> QUERY <q> CIPHERTEXTS <ct> ...` | Exact equality (case-insensitive) |
| `PREFIX <keyring> QUERY <q> CIPHERTEXTS <ct> ...` | Word-boundary prefix match |
| `INDEX <keyring> <b64_plaintext> [FIELD <f>]` | Encrypt + generate search tokens |
| `CONFIG GET <key>` | Get a config value |
| `CONFIG SET <key> <value>` | Set a config value (in-memory only) |
| `CONFIG LIST` | List all config keys and values |
| `HEALTH` | Server + Transit health check |

Options: `[FIELD <f>]` `[CONTEXT <aad>]` `[LIMIT <n>]` `[REWRAP]`

All commands use the RESP3 wire protocol (same framing as Transit).

CONFIG keys include `search.max_batch_size`, `search.default_result_limit`, and `search.decrypt_batch_size`. Since Veil is stateless, CONFIG SET changes are in-memory only and do not persist across restarts.

## Search tokens

For large datasets, `INDEX` generates encrypted search tokens (trigrams + words) using Transit's convergent encryption. At query time, Veil filters candidates by token overlap before decrypting — turning a 50k-decrypt scan into a metadata filter that decrypts only the candidates.

```
# Ingest: encrypt + tokenize
INDEX messages <b64_plaintext> FIELD body CONTEXT chan-42
→ { ciphertext: "AbCd:...", tokens: ["KxPq:...", "MnRs:...", ...] }

# Search: pass tokens alongside ciphertexts for pre-filtering
CONTAINS messages QUERY "dinner" ENTRIES <b64_json_with_tokens>
→ { scanned: 200, matched: 3, filtered: 4800, results: [...] }
```

## Configuration

```toml
[server]
bind = "0.0.0.0:6599"

# Embedded mode (default): configure keyrings and storage directly.
[keyrings.messages]
algorithm = "aes-256-gcm"
rotation_days = 90

[keyrings."messages:tokens"]
algorithm = "aes-256-gcm"
convergent = true

[storage]
data_dir = "./veil-data"

# Remote mode: set transit.addr to use an external Transit server instead.
# [transit]
# addr = "transit.internal:6499"
# tls = true
# token = "veil-service-token"
# pool_size = 8
```

Embedded mode requires `SHROUDB_MASTER_KEY` or `SHROUDB_MASTER_KEY_FILE`.

## Build

```bash
# Default (embedded mode)
cargo build --release

# Remote-only (smaller binary, no crypto/storage deps)
cargo build --release --no-default-features
```

## License

MIT OR Apache-2.0
