# Veil — ShrouDB Repository Analysis

**Component:** shroudb-veil  
**Type:** Engine (7-crate workspace: domain types, engine, protocol, server binary, client SDK, CLI, WASM-capable blind tokenizer)  
**Language:** Rust (edition 2024, MSRV 1.92)  
**License:** MIT OR Apache-2.0  
**Published:** Private registry (`shroudb`), not crates.io. Docker images: `shroudb/veil`, `shroudb/veil-cli`  
**Analyzed:** /Users/nlucas/dev/shroudb/shroudb-veil (v1.4.2)

---

## Role in Platform

Veil is ShrouDB's blind index engine. It enables search over encrypted data without decryption by producing HMAC-SHA256 blind tokens from plaintext and comparing tokens during search. Without Veil, any ShrouDB workflow requiring searchable encrypted fields (e.g., Sigil's `pii: true, searchable: true` annotations) loses search capability entirely — the alternative is full-table decrypt-then-scan, which Veil exists to prevent.

---

## Behavioral Surface

### Public API

**RESP3 wire commands (11):**

| Command | ACL | Description |
|---------|-----|-------------|
| `AUTH <token>` | None | Authenticate connection |
| `PING` | None | Liveness check |
| `HEALTH` | None | Health check |
| `COMMAND LIST` | None | List supported commands |
| `INDEX LIST` | None | List all index names |
| `INDEX CREATE <name>` | Admin | Create index with fresh HMAC key |
| `INDEX INFO <name>` | Read(`veil.{name}.*`) | Get index metadata + entry count |
| `TOKENIZE <idx> <b64> [FIELD f]` | Read(`veil.{idx}.*`) | Generate blind tokens without storing |
| `PUT <idx> <id> <b64> [FIELD f] [BLIND]` | Write(`veil.{idx}.*`) | Store blind tokens for entry |
| `DELETE <idx> <id>` | Write(`veil.{idx}.*`) | Remove entry tokens |
| `SEARCH <idx> <q> [MODE m] [FIELD f] [LIMIT n] [BLIND]` | Read(`veil.{idx}.*`) | Search blind index |

**Search modes:** exact (all words match, score=1.0), contains (any word, scored by overlap), prefix (trigram overlap >= 0.6), fuzzy (trigram overlap >= 0.3).

**BLIND mode:** Client pre-tokenizes and HMACs locally via `shroudb-veil-blind` crate, sends `BlindTokenSet` JSON. Server never sees plaintext. Enables true E2EE search.

**Rust SDK (`shroudb-veil-client`):** Async TCP client with typed methods mirroring each command. Single-connection, auto-reconnect.

**Library API (`shroudb-veil-engine`):** `VeilEngine<S: Store>` is generic over storage backend. Core methods: `index_create`, `index_list`, `index_info`, `tokenize`, `put`, `delete`, `search`, `reconcile_orphans`.

### Core operations traced

**1. PUT (standard mode):** Client sends base64 plaintext → protocol parses `VeilCommand::Put` → ACL check (namespace write) → `engine.put()` decodes base64 → `tokenizer::extract_text()` extracts from JSON or raw → `tokenizer::tokenize()` produces words + trigrams → `hmac_ops::blind_token_set()` HMACs each token with per-index key → serializes `BlindTokenSet` JSON → `store.put()` persists to `veil.{index}` namespace → increments cached entry count → emits Chronicle audit event.

**2. SEARCH (exact mode):** Client sends query text → protocol parses `VeilCommand::Search` → ACL check (namespace read) → `engine.search()` tokenizes and blinds query → paginated `store.list()` over `veil.{index}` namespace in batches of 100 → for each entry, deserializes `BlindTokenSet` → `search::score_entry()` checks all query word tokens present in entry → bounded min-heap keeps top-N by score → early exit after `limit` matches (all 1.0) → sorts descending → emits audit event.

**3. BLIND PUT (E2EE):** Client calls `tokenize_and_blind(&key, plaintext)` locally → `encode_for_wire()` produces base64 JSON → sends `PUT idx id <b64> BLIND` → server decodes base64 → validates JSON is `BlindTokenSet` → stores directly → never sees plaintext.

### Capability gating

No explicit capability trait defined in this repo. `VeilOps` is referenced in ABOUT.md and CLAUDE.md as a capability trait consumed by Sigil, but is defined downstream (in shroudb-sigil), not here. The engine is generic over `Store` — the only gate is what `Store` implementation is provided at construction.

`max_entries_per_index` in `VeilConfig` provides a soft capacity limit (0 = unlimited). Updates to existing entries bypass the limit; only new entries are blocked.

---

## Cryptographic Constructs

**HMAC-SHA256 blind tokens:** Per-index 32-byte key generated via `ring::rand::SystemRandom` (OS CSPRNG). Each plaintext token (word or trigram) is HMAC'd with `ring::hmac::Key::new(HMAC_SHA256, key)` → `ring::hmac::sign()`. Output: 32-byte digest, hex-encoded to 64-char string. Deterministic: same key + same token = same blind token. This is the core construct — enables equality comparison without plaintext.

**Key material handling:** Keys stored as hex-encoded strings in `Zeroizing<String>` (zeroize crate). At use time, hex-decoded into `SecretBytes` (shroudb-crypto, mlock'd, zeroized on drop). Keys are generated once per index and never rotated (no rotation mechanism exists).

**HKDF-SHA256 key derivation (client-side, veil-blind crate):** `BlindKey::derive(shared_secret, info)` uses HKDF extract/expand to derive a 32-byte blind key from a shared secret (e.g., x25519 key exchange output). Enables deterministic key agreement for E2EE workflows without transmitting the key.

**Master key:** `SHROUDB_MASTER_KEY` (base64-encoded 32 bytes) is used by `shroudb-server-bootstrap` to open encrypted storage. Index HMAC keys are stored encrypted at rest via the storage layer — Veil itself does not implement envelope encryption, it delegates to `shroudb-storage`.

**No key rotation.** No key destruction API. No forward secrecy for stored tokens. A compromised index key enables offline brute-force of all tokens in that index.

---

## Engine Relationships

### Calls out to

- **shroudb-store** — All persistence: namespace creation, key-value put/get/delete/list with cursor pagination. Generic trait, injected at construction.
- **shroudb-storage** — Concrete `EmbeddedStore` implementation used in standalone server mode. Provides encrypted-at-rest storage.
- **shroudb-crypto** — `SecretBytes` type for mlock'd key material. Key generation infrastructure.
- **shroudb-acl** — `check_dispatch_acl()` for RESP3 command authorization. `AuthContext`, `AclRequirement`, `Grant`, `Scope` types. `ServerAuthConfig` for token validation config.
- **shroudb-chronicle-core** — `ChronicleOps` trait for audit event emission (INDEX_CREATE, PUT, DELETE, SEARCH, RECONCILE).
- **shroudb-protocol-wire** — `Resp3Frame` types, `read_frame()`/`write_frame()` for wire encoding.
- **shroudb-server-tcp** — `ServerProtocol` trait implemented by `VeilProtocol` for TCP listener.
- **shroudb-server-bootstrap** — Logging, core dump disabling, master key loading, storage opening.
- **shroudb-client-common** — `Connection` type used by `VeilClient`.
- **ring** — HMAC-SHA256 signing, CSPRNG (`SystemRandom`), HKDF.

### Called by

- **shroudb-moat** — Embeds `VeilEngine` + `shroudb-veil-protocol::dispatch()`. Routes RESP3 frames with `VEIL` prefix. Constructs engine with shared `Store` at startup.
- **shroudb-sigil** — Consumes Veil via `VeilOps` capability trait for searchable encrypted field annotations. Calls TOKENIZE at write time, SEARCH at query time.
- **shroudb-codegen** — Reads `protocol.toml` for code generation.

### Sentry / ACL integration

Three-tier authorization:

1. **Moat level:** `check_moat_auth()` evaluates Moat's auth policy against engine + command ACL. Returns RESP3 error frame on denial.
2. **Protocol level:** `shroudb_acl::check_dispatch_acl(auth_context, acl_requirement)` — first line of `dispatch()`. Commands declare ACL via `VeilCommand::acl_requirement()` → `AclRequirement::None | Admin | Namespace { ns, scope }`.
3. **Engine level:** Optional `PolicyEvaluator` (ABAC) checked before PUT, DELETE, SEARCH, INDEX_CREATE. Returns `VeilError::PolicyDenied`.

Standalone server uses `shroudb-acl` token-based auth directly. Moat-embedded mode uses Moat's policy layer, which sets `is_platform=true` in the forwarded AuthContext (platform tokens bypass protocol-level ACL; Moat's own check is the gatekeeper).

No direct Sentry engine integration. ACL is provided by `shroudb-acl` (the built-in fallback), not the Sentry engine.

---

## Store Trait

Veil is generic over `S: Store` (from `shroudb-store`). It does not implement the Store trait — it consumes it.

**Storage operations used:** `put`, `get`, `delete`, `list` (paginated, cursor-based, batches of 100), `namespace_create`.

**Namespaces:** `veil.indexes` (index metadata + encrypted HMAC keys), `veil.{index_name}` (entry BlindTokenSets keyed by entry ID).

**Standalone mode:** Uses `shroudb_storage::EmbeddedStore` (on-disk encrypted storage). Data directory configurable via `VEIL_DATA_DIR` or `store.data_dir` in config.

**Moat mode:** Receives a shared `Store` reference from Moat. Supports per-engine storage assignment (Moat can route Veil's namespaces to a dedicated backend).

**No migration tooling within this repo.** WAL-based topology migration is handled by `shroudb-wal-tool`.

---

## Licensing Tier

**Tier:** Open core (MIT OR Apache-2.0)

The entire repository — all 7 crates — is MIT OR Apache-2.0. No feature flags fence commercial behavior. No capability traits gate licensed features. The commercial fence is at the repo level: Veil is open, while engines like Cipher, Sentry, and Sigil are closed source. The open license covers all of Veil's functionality including E2EE (BLIND mode), all search modes, and the client-side WASM tokenizer.

Published to private `shroudb` registry, not crates.io. Docker images are public-facing.

---

## Standalone Extractability

**Extractable as independent product:** Yes, with moderate work.

Veil is already a standalone TCP server with its own Docker image, CLI, and client SDK. The primary coupling is to the `shroudb-store` / `shroudb-storage` / `shroudb-crypto` commons crates for persistence and key management. To fully extract:

1. **Replace storage layer** — implement `Store` trait against a standard backend (SQLite, RocksDB, S3). The trait is small (put/get/delete/list/namespace_create).
2. **Replace key management** — swap `shroudb-crypto::SecretBytes` and `shroudb-server-bootstrap` master key loading with a standalone KMS integration or local keyring.
3. **Remove ACL dependency** — simplify to API key auth or integrate a standard RBAC library. `shroudb-acl` is small but tightly typed.
4. **Remove Chronicle** — audit logging is optional (constructor takes `Option<Arc<dyn ChronicleOps>>`). Can be replaced with any structured logger.

Value lost without sibling engines: Sigil integration (automated searchable encrypted fields from schema annotations), Cipher integration (decrypt/re-encrypt flows), and Moat embedding (single-binary deployment). As a standalone, it's a blind index service, not an integrated encrypted database search layer.

### Target persona if standalone

Security-conscious application teams that need encrypted search without building their own. Healthcare (HIPAA), finance (PCI-DSS), legal (privilege-tagged document search). Teams using client-side encryption that need server-side search without key exposure (BLIND mode).

### Pricing model fit if standalone

**Usage-based** (indexed entries + search queries) or **open core + support** (the code is already MIT/Apache-2.0; sell hosted service, enterprise support, and SLA). The WASM client-side tokenizer enables a freemium developer experience — local blinding is free, hosted search is paid.

---

## Deployment Profile

**Standalone binary:** `shroudb-veil` TCP server on port 6799. RESP3 wire protocol. No HTTP surface. Alpine 3.21 Docker images (multi-arch: amd64 + arm64). Non-root user (UID 65532). `/data` volume for persistence.

**Embedded in Moat:** Protocol crate's `dispatch()` function called by Moat's router. Engine constructed with shared Store at Moat startup. No separate process.

**Library mode:** `shroudb-veil-engine` crate is a library. Any Rust application can construct `VeilEngine<S>` with a custom Store implementation.

**Client-side (WASM):** `shroudb-veil-blind` crate compiles to `wasm32-unknown-unknown` with `--features wasm`. Enables browser-based E2EE tokenization via `crypto.getRandomValues`.

**Infrastructure dependencies:** Disk (or a Store backend) for persistence. Master key for storage encryption (env var or file). No external services required. Self-hostable without expertise — single binary, single config file.

---

## Monetization Signals

**`max_entries_per_index`:** Capacity limit in `VeilConfig`. Unlimited by default (0). Only enforced on new entries, not updates. This is a quota enforcement hook — set it to a tier limit for commercial plans.

**No other monetization signals present.** No usage counters, no API key quotas, no rate limiting, no tenant-scoped billing meters, no license key validation. The engine is functionally unbounded. Any commercial gating would need to be applied at the Moat or infrastructure layer, or added to the engine config.

---

## Architectural Moat (Component-Level)

**The moat is moderate and primarily platform-level, not component-level.**

What's non-trivial in this component specifically:

1. **Trigram + word dual-token scheme** — The combination of word tokens for exact/contains matching and character trigrams for prefix/fuzzy matching in a single blind index is a well-designed search primitive. It's not novel research, but it's a correct implementation of a non-obvious design that balances search quality against token storage cost.

2. **E2EE blind search with WASM** — The `veil-blind` crate enabling client-side tokenization + HKDF key derivation + WASM compilation is a genuine differentiator. Competitors offering encrypted search typically require server-side plaintext ingestion. True E2EE search where the server never sees plaintext is rare.

3. **Bounded min-heap search with early exit** — Memory-efficient O(limit) search regardless of index size, with early termination for exact mode. Correct implementation but reproducible.

4. **Zeroization discipline** — Consistent use of `Zeroizing<String>` and `SecretBytes` for all key material paths. Not unique, but shows crypto-aware engineering.

The deeper moat is platform integration: Sigil's annotation-driven blind indexing, Moat's unified deployment, Chronicle audit trails, and the ACL layer. Veil alone is a competent blind index service; Veil inside ShrouDB is an integrated encrypted search layer.

---

## Gaps and Liabilities

**No key rotation.** HMAC keys are immutable per index lifetime. A compromised key requires creating a new index, re-indexing all entries, and migrating consumers. No API or tooling exists for this. This is the most significant operational gap.

**No key destruction API.** Cannot cryptographically shred an index by destroying its key material. Delete removes tokens but the key persists in the store until garbage collected.

**Linear scan search.** Every search scans all entries in the index (paginated in batches of 100). No inverted index, no token-to-entry mapping. For large indexes (>100K entries), search latency will degrade linearly. The bounded heap limits memory, but not I/O.

**No streaming.** All store operations buffer results. Large reconcile operations or searches on big indexes hold all data in memory during processing.

**No forward secrecy.** Tokens are deterministic — same plaintext always produces the same token. An attacker with the HMAC key can precompute a dictionary and match stored tokens offline.

**TOKENIZER_VERSION (v1) with no migration path.** The `veil-blind` crate declares `TOKENIZER_VERSION: u32 = 1` with a comment "bump on algorithm changes; requires re-indexing all entries." No tooling exists for this re-indexing.

**No HTTP/gRPC surface.** RESP3-only. Integration from non-Rust languages requires either implementing the RESP3 client protocol or going through the CLI. No OpenAPI surface for web services.

**Entry count tracking is eventually consistent.** Uses `AtomicU64` with `Ordering::Relaxed` and no cross-operation locking. Under high concurrency, `index_info` entry counts may briefly drift from reality.

**`reconcile_orphans` has no caller in this repo.** The API exists but is only useful when called by Moat or an operator with an authoritative list of valid IDs from an upstream engine.

---

## Raw Signals for Evaluator

- **Open core loss leader pattern:** Veil is MIT/Apache-2.0 while higher-value engines (Cipher, Sentry, Sigil) are closed source. Veil's value proposition increases dramatically when composed with those engines. Open-sourcing Veil attracts developers who then need the commercial engines for production.

- **Registry is private.** Despite MIT license, crates are published to `shroudb` registry (not crates.io). Docker build requires `registry_token` secret. This means "open source" in license but not in distribution — users must build from source or access the private registry.

- **WASM is a distribution channel.** `veil-blind` with WASM support enables browser SDKs and edge computing use cases without a full Rust toolchain. This is a strategic asset for developer adoption.

- **No telemetry, no phone-home.** The engine is fully self-contained. No license validation, no usage reporting. Commercial enforcement must be contractual or infrastructure-gated.

- **Chronicle integration is optional.** Audit logging is injected via `Option<Arc<dyn ChronicleOps>>`. In standalone mode without Chronicle, operations are unaudited. For compliance-sensitive deployments, this gap must be filled.

- **The `reconcile_orphans` API reveals platform coupling.** It assumes an authoritative upstream source of truth for entry IDs. This only makes sense in the Moat/Sigil context where Sigil owns the entity lifecycle and Veil maintains a derived index.

- **Test coverage is comprehensive.** Engine, protocol, and blind crates all have thorough unit tests including proptest fuzzing for name validation. Concurrent put tests verify thread safety. E2EE round-trip tests verify client-server compatibility.

- **Edition 2024 / MSRV 1.92 signals active maintenance** and willingness to adopt latest Rust features. Not a legacy codebase.
