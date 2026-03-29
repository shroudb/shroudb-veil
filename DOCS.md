# ShrouDB Veil — Documentation

## Overview

Veil is a blind index engine that enables searching over encrypted data without decrypting it. It uses HMAC-SHA256 to derive deterministic blind tokens from plaintext, stores those tokens, and compares them during search — never exposing the original data.

## Concepts

### Blind Indexing

Traditional databases search by comparing plaintext values. When data is encrypted at rest, you face a choice: decrypt everything to search (slow, insecure) or maintain a separate search index (Veil's approach).

Veil's blind indexing:
1. Takes plaintext and produces deterministic tokens via HMAC-SHA256
2. Stores only the HMAC tokens — never the plaintext
3. Searches by HMAC-ing the query and comparing tokens
4. Guarantees: same plaintext + same key → same token (enables equality comparison)

### Indexes

Each blind index is an independent search namespace with its own HMAC key. Indexes are isolated — an entry in one index is invisible to searches in another.

### Tokenization

Plaintext is processed into two types of tokens:

- **Word tokens** (`w:{word}`): The text is lowercased, split on non-alphanumeric boundaries. Each word becomes a token. Used for exact and contains matching.
- **Trigram tokens** (`t:{trigram}`): For words with 3+ characters, sliding windows of 3 characters. Used for prefix and fuzzy matching.

Example: "Hello World" → words: `w:hello`, `w:world` | trigrams: `t:hel`, `t:ell`, `t:llo`, `t:wor`, `t:orl`, `t:rld`

### Match Modes

| Mode | Algorithm | Use Case |
|------|-----------|----------|
| **exact** | All query word tokens must appear in entry | "Find records containing all these words" |
| **contains** | Any query word token matches; score = overlap ratio | "Find records containing any of these words" |
| **prefix** | Trigram overlap ≥ 60%; captures leading characters | "Find records starting with..." |
| **fuzzy** | Trigram overlap ≥ 30%; captures similar strings | "Find records similar to..." |

### Scoring

- **Exact:** 1.0 if all query word tokens match, otherwise no match.
- **Contains:** matched_words / total_query_words.
- **Prefix/Fuzzy:** matched_trigrams / total_query_trigrams. Results below threshold are excluded.

Results are sorted by descending score.

## Wire Protocol

Veil uses RESP3 over TCP (port 6799 by default).

**Request format:** RESP3 array of bulk strings.
**Response format:** JSON bulk string (success) or RESP3 simple error (failure).

### Command Reference

#### INDEX CREATE

Create a new blind index.

```
INDEX CREATE users
→ {"status":"ok","index":"users","created_at":1711700000}
```

#### INDEX LIST

List all index names.

```
INDEX LIST
→ ["users","contacts"]
```

#### INDEX INFO

Get index metadata.

```
INDEX INFO users
→ {"index":"users","created_at":1711700000,"entry_count":42}
```

#### TOKENIZE

Generate blind tokens without storing. Useful for external callers (e.g., Sigil) that need tokens for their own storage.

```
TOKENIZE users SGVsbG8gV29ybGQ=
→ {"status":"ok","words":2,"trigrams":5,"tokens":{"words":["a1b2...","c3d4..."],"trigrams":[...]}}
```

With field extraction:
```
TOKENIZE users eyJuYW1lIjoiQWxpY2UifQ== FIELD name
```

#### PUT

Tokenize plaintext and store the blind tokens.

```
PUT users u1 QWxpY2UgSm9obnNvbg==
→ {"status":"ok","id":"u1","version":1}
```

With field extraction:
```
PUT contacts c1 eyJuYW1lIjoiQWxpY2UiLCJjaXR5IjoiUG9ydGxhbmQifQ== FIELD name
```

Putting to an existing ID overwrites the tokens.

#### DELETE

Remove an entry's blind tokens.

```
DELETE users u1
→ {"status":"ok","id":"u1"}
```

#### SEARCH

Search a blind index.

```
SEARCH users johnson MODE exact LIMIT 10
→ {"status":"ok","scanned":100,"matched":2,"results":[{"id":"u1","score":1.0},{"id":"u3","score":1.0}]}
```

Parameters:
- `MODE` — exact, contains (default), prefix, fuzzy
- `FIELD` — JSON field to extract from query (not commonly used for search)
- `LIMIT` — Maximum results (default: 100)

## Authentication

Veil uses token-based auth via `shroudb-acl`. When `[auth] method = "token"` is configured:

1. Client connects via TCP
2. Client sends `AUTH <token>`
3. Server validates token and establishes an AuthContext
4. Each subsequent command is checked against the token's grants

ACL scopes:
- **Public** (no auth needed): HEALTH, PING, INDEX LIST, COMMAND LIST
- **Admin**: INDEX CREATE
- **Namespace Read** (`veil.{index}.*`): SEARCH, TOKENIZE, INDEX INFO
- **Namespace Write** (`veil.{index}.*`): PUT, DELETE

## Deployment

### Standalone

```bash
SHROUDB_MASTER_KEY="<base64-32-bytes>" shroudb-veil --config config.toml
```

### Embedded in Moat

The protocol crate's `dispatch()` function is what Moat calls. The engine crate is constructed with a Store reference at Moat startup.

### Docker

Multi-arch images (amd64 + arm64) based on Alpine 3.21. Non-root user (UID 65532). `/data` volume for persistence.

## Security

- **HMAC keys** are generated via CSPRNG (32 bytes) and stored encrypted in ShrouDB
- **No plaintext at rest** — only HMAC tokens are stored
- **No plaintext during search** — search compares blind tokens only
- **Core dumps disabled** on both Linux and macOS
- **Fail-closed auth** — missing token, insufficient grants → error
- **Key material zeroized** via `SecretBytes` after use
