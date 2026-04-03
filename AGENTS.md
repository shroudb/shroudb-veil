# Veil — Agent Instructions

> Blind index engine: HMAC-based searchable encryption over encrypted data without decrypting it. Tokenizes plaintext into word/trigram tokens, blinds them with per-index HMAC-SHA256 keys, and compares blind tokens for search.

## Quick Context

- **Role in ecosystem**: Encrypted search — enables querying encrypted data without exposing plaintext. Sigil calls Veil for `searchable` PII fields.
- **Deployment modes**: embedded | remote (TCP port 6799)
- **Wire protocol**: RESP3
- **Backing store**: ShrouDB Store trait (encrypted at rest)

## Workspace Layout

```
shroudb-veil-core/      # BlindIndex, MatchMode, TokenSet, VeilError
shroudb-veil-engine/    # VeilEngine, IndexManager, tokenizer, hmac_ops, search scoring
shroudb-veil-protocol/  # RESP3 command parsing + dispatch
shroudb-veil-server/    # Standalone TCP binary
shroudb-veil-client/    # Typed Rust SDK
shroudb-veil-cli/       # CLI tool
shroudb-veil-blind/     # Client-side tokenizer + HMAC blinding for E2EE (BLIND mode)
```

## RESP3 Commands

### Index Management

| Command | Args | Returns | Description |
|---------|------|---------|-------------|
| `INDEX CREATE` | `<name>` | `{status, index, created_at}` | Create blind index with CSPRNG HMAC key (Admin) |
| `INDEX LIST` | — | `[names]` | List all index names |
| `INDEX INFO` | `<name>` | `{index, created_at, entry_count}` | Index metadata |

### Token Operations

| Command | Args | Returns | Description |
|---------|------|---------|-------------|
| `TOKENIZE` | `<index> <plaintext_b64> [FIELD <name>]` | `{status, words, trigrams, tokens}` | Pure operation: generate blind tokens (no storage) |

### Entry Operations

| Command | Args | Returns | Description |
|---------|------|---------|-------------|
| `PUT` | `<index> <id> <plaintext_b64> [FIELD <name>] [BLIND]` | `{status, id, version}` | Tokenize + blind + store (BLIND: client provides pre-computed tokens) |
| `DELETE` | `<index> <id>` | `{status, id}` | Remove entry from index |

### Search

| Command | Args | Returns | Description |
|---------|------|---------|-------------|
| `SEARCH` | `<index> <query> [MODE exact\|contains\|prefix\|fuzzy] [FIELD <name>] [LIMIT <n>] [BLIND]` | `{status, scanned, matched, results}` | Search by blind token comparison (BLIND: query is pre-computed tokens) |

### Operational

| Command | Args | Returns | Description |
|---------|------|---------|-------------|
| `AUTH` | `<token>` | `{status}` | Authenticate |
| `HEALTH` | — | `{status}` | Health check |
| `PING` | — | `PONG` | Liveness |
| `COMMAND LIST` | — | `{count, commands}` | List commands |

### Command Examples

```
> INDEX CREATE users
{"status":"ok","index":"users","created_at":1711843200}

> PUT users alice YWxpY2Ugam9obnNvbg== FIELD name
{"status":"ok","id":"alice","version":1}

> SEARCH users "alice" MODE contains FIELD name LIMIT 10
{"status":"ok","scanned":50,"matched":1,"results":[{"id":"alice","score":1.0}]}

> PUT users bob <blind_token_set_b64> BLIND
{"status":"ok","id":"bob","version":1}

> SEARCH users <blind_token_set_b64> MODE exact BLIND
{"status":"ok","scanned":50,"matched":1,"results":[{"id":"bob","score":1.0}]}
```

## Search Flow

```
Query → Tokenize → Blind (HMAC-SHA256) → Scan entries → Compare blind tokens → Score → Return hits

1. Retrieve per-index HMAC key from cache
2. Tokenize query: words ("w:alice") + trigrams ("t:ali", "t:lic", "t:ice")
3. Blind each token: HMAC-SHA256(key, token) → hex string
4. Paginate through stored entries (100/page)
5. Deserialize each entry's BlindTokenSet
6. Score based on match mode
7. Sort by score descending, truncate to limit
```

**No plaintext decryption occurs.** Entire search operates on HMAC-derived blind tokens. Same plaintext + same key = same blind token (deterministic).

### Match Modes & Scoring

| Mode | Algorithm | Threshold | Use Case |
|------|-----------|-----------|----------|
| `exact` | All query words must be in entry words | All or nothing (score=1.0) | Precise name search |
| `contains` | At least one query word matches | Any match (score=matched/total) | Keyword search |
| `prefix` | Trigram overlap | ≥60% overlap | Prefix search, typo tolerance |
| `fuzzy` | Trigram overlap | ≥30% overlap | Edit-distance similarity |

## BLIND Mode (E2EE)

When the `BLIND` flag is present on `PUT` or `SEARCH`, the server skips tokenization and blinding. Instead, the client provides pre-computed blind tokens directly.

- **Standard mode:** `data_b64` / `query` = base64-encoded plaintext / plain text. Server tokenizes and blinds.
- **BLIND mode:** `data_b64` / `query` = base64-encoded `BlindTokenSet` JSON. Server stores/searches directly.

The `shroudb-veil-blind` crate provides client-side tokenization and HMAC blinding:
- `BlindKey` — HMAC key for client-side blinding
- `tokenize_and_blind()` — tokenize plaintext and produce a `BlindTokenSet`
- `encode_for_wire()` — base64-encode the result for the wire protocol

This enables E2EE workflows where plaintext never leaves the client.

## Public API (Embedded Mode)

### Core Types

```rust
pub struct BlindIndex { pub name: String, pub key_material: Zeroizing<String>, pub created_at: u64 }
pub enum MatchMode { Exact, Contains, Prefix, Fuzzy }
pub struct TokenSet { pub words: Vec<String>, pub trigrams: Vec<String> }
pub struct BlindTokenSet { pub words: Vec<String>, pub trigrams: Vec<String> }  // hex HMAC values
pub struct SearchResult { pub hits: Vec<SearchHit>, pub scanned: usize, pub matched: usize }
pub struct SearchHit { pub id: String, pub score: f64 }
```

### Usage Pattern

```rust
use shroudb_veil_engine::{VeilEngine, VeilConfig};

let engine = VeilEngine::new(store.clone(), VeilConfig { default_result_limit: 100 }).await?;

engine.index_create("users").await?;
engine.put("users", "alice", &base64_encode(b"alice johnson"), Some("name")).await?;

let results = engine.search("users", "alice", MatchMode::Contains, Some("name"), Some(10)).await?;
```

## Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `server.tcp_bind` | `SocketAddr` | `"0.0.0.0:6799"` | TCP listen address |
| `store.data_dir` | `PathBuf` | `"./veil-data"` | Data directory |
| `engine.default_result_limit` | `usize` | `100` | Default SEARCH limit |
| `engine.indexes` | `Vec<String>` | `[]` | Pre-seed indexes on startup |

## Data Model

| Namespace | Key | Value | Purpose |
|-----------|-----|-------|---------|
| `veil.indexes` | Index name | JSON `BlindIndex` (name, hex HMAC key, created_at) | Index metadata |
| `veil.{index_name}` | Entry ID | JSON `BlindTokenSet` (arrays of hex HMAC tokens) | Blind tokens per entry |

### Tokenization

- **Words**: Lowercase, split on non-alphanumeric. Format: `w:{word}`
- **Trigrams**: 3-char sliding window on words ≥ 3 chars. Format: `t:{tri}`
- Example: `"Alice Johnson"` → words: `["w:alice", "w:johnson"]`, trigrams: `["t:ali", "t:lic", "t:ice", "t:joh", "t:ohn", "t:hns", "t:nso", "t:son"]`

### JSON Field Extraction

If `FIELD <name>` specified: extract that field's string value from JSON. Otherwise: concatenate all string values.

## Common Mistakes

- Search is O(N) over entries in the time range — for large indexes, this is a full scan. Index design matters.
- Blind tokens are deterministic: same plaintext + same index key = same tokens. This is by design (enables search) but means identical values are linkable within an index.
- Different indexes have different HMAC keys — tokens from one index cannot be compared against another.
- `TOKENIZE` is a pure operation (no storage). Use it for debugging; use `PUT` for actual indexing.
- `key_material` is `Zeroizing<String>` — it's erased from memory on drop.

## Related Crates

| Crate | Relationship |
|-------|-------------|
| `shroudb-store` | Provides Store trait for index/token persistence |
| `shroudb-crypto` | HMAC-SHA256, CSPRNG key generation |
| `shroudb-sigil` | Calls Veil for `searchable` PII fields via `VeilOps` trait |
| `shroudb-veil-blind` | Client-side tokenizer + HMAC blinding for E2EE BLIND mode |
| `shroudb-moat` | Embeds Veil; wires Cipher dependency for Sigil integration |
