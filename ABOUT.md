# Understanding ShrouDB Veil

This document explains ShrouDB Veil at two levels of depth. Pick the section that matches your background.

---

## For Everyone: What ShrouDB Veil Does

Encryption protects data — but it also makes it unsearchable. If you encrypt a database of customer emails, you can't search for "alice@example.com" without decrypting every single record first. This creates a painful trade-off: security or usability, pick one.

**ShrouDB Veil is an encrypted search engine.** It lets you search over encrypted data without the data ever leaving Veil's memory in plaintext form. You send in a batch of encrypted values and a search query. Veil decrypts each value, checks if it matches, wipes the plaintext from memory, and returns which entries matched — along with a relevance score. The plaintext is never sent back over the network.

**What it provides:**

- **Four search modes** — Exact match, substring (contains), prefix, and fuzzy (typo-tolerant) search over encrypted data.
- **Token-based pre-filtering** — Optional search tokens let Veil skip entries that can't possibly match, avoiding unnecessary decryption. This dramatically speeds up searches over large datasets.
- **Automatic indexing** — The INDEX command encrypts plaintext and generates search tokens in one step, ready for storage.
- **Key rotation on search** — Optionally re-encrypt matched entries under the current key during search (the REWRAP flag), enabling opportunistic key rotation.
- **JSON field search** — Search specific fields within encrypted JSON documents.

**Why it matters:**

- Sensitive data stays encrypted in your database. Veil decrypts only during search and immediately wipes the plaintext.
- No plaintext is ever returned to the caller — only match indicators and relevance scores.
- Fuzzy search tolerates typos (Levenshtein distance up to 2), making it practical for real user queries.
- Token pre-filtering means you can search over tens of thousands of encrypted entries efficiently.

---

## For Technical Leaders: Architecture and Trade-offs

### The Problem

End-to-end encryption and searchability are traditionally at odds. Schemes like homomorphic encryption or order-preserving encryption exist but are either too slow for production use or leak too much information. In practice, teams either store searchable fields in plaintext (defeating encryption) or give up on search entirely.

### What ShrouDB Veil Is

ShrouDB Veil is a **server-side encrypted search engine** that decrypts data in memory, matches it, and discards the plaintext — all within a single server process. It delegates all cryptographic operations to ShrouDB Transit (either embedded in-process or as a remote server), ensuring that encryption keys never enter Veil's own code paths.

### Key Architectural Decisions

| Decision | Rationale |
|----------|-----------|
| **Decrypt-match-discard model** | Plaintext exists only in server memory during the match operation. Never persisted, never returned over the network. Acceptable for moderate-scale datasets where Transit can decrypt at sufficient throughput. |
| **Transit delegation** | All encryption/decryption is handled by ShrouDB Transit. Veil never touches key material directly. In embedded mode, Transit runs in-process. In remote mode, it's a separate server. |
| **Token pre-filtering** | Convergent-encrypted search tokens allow Veil to skip entries that can't match without decrypting them. Reduces decryption volume by orders of magnitude for selective queries. |
| **Stateless design** | Veil stores no data. Encrypted entries and tokens are provided by the caller per-request. This keeps Veil simple and avoids duplicating storage. |

### Performance Characteristics

Veil's performance is bounded by Transit decryption throughput:
- **Embedded mode:** Direct function calls, no network overhead. Decryption is CPU-bound.
- **Remote mode:** Connection-pooled TCP to Transit. Network latency adds per-batch overhead.
- **Token filtering:** Can eliminate 90%+ of entries before decryption, transforming a 50,000-entry scan into a 500-entry decrypt.

### Operational Model

- **Configuration:** TOML file with search tuning and Transit connection settings.
- **Observability:** Structured audit logging. Telemetry via the shared ShrouDB telemetry foundation.
- **Deployment:** Single static binary. TLS and mTLS supported. Requires Transit (embedded or remote).
