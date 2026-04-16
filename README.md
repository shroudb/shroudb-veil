# ShrouDB Veil

Blind index engine for encrypted search. Enables searching over encrypted data without decrypting it.

## Quick Start

```bash
# Start the server (ephemeral dev mode)
cargo run -p shroudb-veil-server

# In another terminal, use the CLI
cargo run -p shroudb-veil-cli -- INDEX CREATE users
cargo run -p shroudb-veil-cli -- PUT users u1 $(echo -n "Alice Johnson" | base64)
cargo run -p shroudb-veil-cli -- PUT users u2 $(echo -n "Bob Smith" | base64)
cargo run -p shroudb-veil-cli -- SEARCH users johnson MODE exact
```

## Commands

| Command | Description | ACL |
|---------|-------------|-----|
| `INDEX CREATE <name>` | Create a blind index | Admin |
| `INDEX ROTATE <name>` | Rotate HMAC key; clears all entries | Admin |
| `INDEX DESTROY <name>` | Crypto-shred key + delete entries + remove index | Admin |
| `INDEX REINDEX <name>` | Clear entries and update tokenizer version | Admin |
| `INDEX RECONCILE <name> <id1> [id2 ...]` | Remove orphaned entries not in the valid set | Admin |
| `INDEX LIST` | List all indexes | Public |
| `INDEX INFO <name>` | Get index info (entry count, created_at, tokenizer_version) | Read |
| `TOKENIZE <index> <b64> [FIELD <f>]` | Generate blind tokens without storing | Read |
| `PUT <index> <id> <b64> [FIELD <f>] [BLIND]` | Tokenize + store blind tokens | Write |
| `DELETE <index> <id>` | Remove entry from index | Write |
| `SEARCH <index> <query> [MODE m] [FIELD f] [LIMIT n] [BLIND]` | Search the index | Read |
| `HEALTH` | Health check | Public |
| `PING` | Ping-pong | Public |
| `AUTH <token>` | Authenticate connection | Public |
| `COMMAND LIST` | List supported commands | Public |

### Search Modes

- **exact** — All query words must appear in the entry. Score = 1.0 on match.
- **contains** (default) — Any query word matches. Score = matched/total query words.
- **prefix** — Trigram overlap with 0.6 threshold. Captures prefix similarity.
- **fuzzy** — Trigram overlap with 0.3 threshold. Captures edit-distance similarity.

### JSON Field Extraction

When indexing JSON data, use `FIELD <name>` to extract a specific field:

```
PUT contacts c1 eyJuYW1lIjoiQWxpY2UiLCJjaXR5IjoiUG9ydGxhbmQifQ== FIELD name
```

Without `FIELD`, all string values in the JSON object are concatenated.

### BLIND Mode (E2EE)

For end-to-end encrypted workflows where plaintext must never reach the server, use the `BLIND` flag. The client pre-computes blind tokens locally using the `shroudb-veil-blind` crate and sends them directly:

```
PUT users u1 <blind_token_set_b64> BLIND
SEARCH users <blind_token_set_b64> MODE exact BLIND
```

In standard mode (no `BLIND`): `data_b64` is base64-encoded plaintext and `query` is plain text. The server tokenizes and blinds.

In `BLIND` mode: `data_b64` is a base64-encoded `BlindTokenSet` JSON, and `query` is a base64-encoded `BlindTokenSet` JSON. The server stores and searches them directly without touching plaintext.

The `shroudb-veil-blind` crate provides client-side tokenization and HMAC blinding via `BlindKey`, `tokenize_and_blind()`, and `encode_for_wire()`.

## Configuration

```toml
[server]
tcp_bind = "0.0.0.0:6799"

[store]
mode = "embedded"
data_dir = "./veil-data"

[engine]
default_result_limit = 100
# Pre-seed indexes on startup
indexes = ["users", "contacts"]

# Token-based auth (optional)
[auth]
method = "token"

[auth.tokens.my-token]
tenant = "tenant-a"
actor = "my-app"
platform = false
grants = [
    { namespace = "veil.users.*", scopes = ["read", "write"] },
]
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `VEIL_CONFIG` | Path to config file |
| `VEIL_DATA_DIR` | Data directory |
| `VEIL_TCP_BIND` | TCP bind address |
| `VEIL_HTTP_BIND` | HTTP bind address (optional REST API) |
| `VEIL_LOG_LEVEL` | Log level (info, debug, warn) |
| `VEIL_ADDR` | CLI: server address (default: 127.0.0.1:6799) |
| `SHROUDB_MASTER_KEY` | Base64-encoded 32-byte master key |
| `SHROUDB_MASTER_KEY_FILE` | Path to master key file |

## Architecture

```
shroudb-veil-core/        — Domain types (BlindIndex, MatchMode, TokenSet)
shroudb-veil-engine/      — Store-backed engine (VeilEngine, IndexManager, HMAC ops)
shroudb-veil-protocol/    — RESP3 command parsing + dispatch
shroudb-veil-server/      — TCP server binary
shroudb-veil-client/      — Rust client SDK
shroudb-veil-cli/         — CLI tool
shroudb-veil-blind/       — Client-side tokenizer + HMAC blinding for E2EE workflows
```

### How Blind Indexing Works

1. **Index creation:** A per-index HMAC-SHA256 key is generated via CSPRNG and stored encrypted in ShrouDB.
2. **Tokenization:** Plaintext is normalized to lowercase, split on non-alphanumeric boundaries, producing word tokens (`w:hello`) and character trigrams (`t:hel`, `t:ell`, `t:llo`).
3. **Blinding:** Each token is HMAC'd with the index key → deterministic blind token. Same input + same key = same output.
4. **Storage:** Blind tokens are stored in ShrouDB keyed by entry ID.
5. **Search:** Query is tokenized and HMAC'd with the same key. Blind tokens are compared (set intersection). No decryption occurs.

### Namespace Convention

```
veil.indexes        — Index configurations (name, key material, timestamps)
veil.{index_name}   — Blind token entries for each index
```

## Docker

```bash
# Server
docker run -v veil-data:/data -p 6799:6799 \
  -e SHROUDB_MASTER_KEY="<base64-key>" \
  shroudb/veil

# CLI
docker run --rm shroudb/veil-cli --addr host.docker.internal:6799 HEALTH
```

## License

MIT OR Apache-2.0
