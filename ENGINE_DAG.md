# Veil Engine DAG

## Overview

Veil is ShrouDB's blind index engine for encrypted search. It tokenizes plaintext
(word + character trigram) and applies HMAC-SHA256 per-index keys to produce
deterministic blind tokens, which are stored and compared without ever decrypting
the underlying data. The engine is generic over the `shroudb-store` `Store` trait,
so the same logic runs embedded (in-process) or against a remote ShrouDB server
over TCP. Four match modes are supported: `exact`, `contains`, `prefix`, and
`fuzzy`. A separate `shroudb-veil-blind` crate performs the same tokenize-and-HMAC
pipeline client-side so that plaintext never leaves the client in E2EE workflows.

## Crate dependency DAG

Internal crates only (workspace version 1.8.1). Arrows point from consumer to
dependency.

```
                         shroudb-veil-cli
                                |
                                v
                       shroudb-veil-client
                                |
                                |  (via shroudb-client-common; no direct
                                |   dep on veil-core/engine/protocol)
                                |
      +-------------------------+---------------------------+
      |                                                     |
      |                                                     |
shroudb-veil-server <---- shroudb-veil-protocol             |
      |         \                |                          |
      |          \               v                          |
      |           +------> shroudb-veil-engine              |
      |                          |                          |
      |                          v                          |
      +-------------------> shroudb-veil-core <----- shroudb-veil-blind
```

Notes:

- `shroudb-veil-core` is the shared-types root: `BlindIndex`, `MatchMode`,
  `TokenSet`, `VeilError`, and the versioned `tokenizer` module (including
  `TOKENIZER_VERSION`).
- `shroudb-veil-blind` depends only on `shroudb-veil-core` (for the tokenizer
  contract) plus `ring` for HMAC. It does NOT depend on `shroudb-veil-engine`
  or `shroudb-store`, which is what makes it safe to embed in clients or
  compile to WASM (the `wasm` feature pulls in `getrandom` with the `js`
  backend).
- `shroudb-veil-protocol` pulls in `shroudb-veil-engine`, `shroudb-acl`,
  `shroudb-store`, and `shroudb-protocol-wire` to dispatch RESP3 commands.
- `shroudb-veil-engine` also depends on `shroudb-audit` and
  `shroudb-chronicle-core` (for the `ChronicleOps` trait) plus
  `shroudb-server-bootstrap` (for the `Capability<T>` capability-slot type
  used to wire Sentry / Chronicle explicitly).
- `shroudb-veil-server` is the default workspace member and the standalone
  TCP/HTTP binary (`shroudb-veil`). It composes engine + protocol + storage
  + bootstrap + TCP server crates.
- `shroudb-veil-client` is a thin SDK over `shroudb-client-common` and does
  not import engine types.

## Capabilities

- **Exact match** — every query word token must be present in the entry's
  stored blind token set (`MatchMode::Exact`).
- **Contains match** — at least one query word token intersects the entry's
  word tokens; score reflects overlap (`MatchMode::Contains`, the default for
  `SEARCH`).
- **Prefix match** — trigram overlap tuned to capture leading-character
  similarity (`MatchMode::Prefix`).
- **Fuzzy match** — trigram overlap with a lower threshold to capture
  edit-distance similarity (`MatchMode::Fuzzy`).
- **JSON field scoping** — `PUT`, `SEARCH`, and `TOKENIZE` accept an optional
  `FIELD <name>` argument that extracts a single string value out of a JSON
  document before tokenizing. This lets one entry support multiple searchable
  fields under one index.
- **Store-namespace scoping** — each index owns private `tokens_namespace(name)`
  and inverted-index namespaces in the backing Store, keeping blind tokens
  isolated per index.
- **Index lifecycle** — `INDEX CREATE`, `INDEX INFO`, `INDEX LIST`,
  `INDEX ROTATE` (new HMAC key, wipes entries), `INDEX REINDEX` (keep key,
  bump `tokenizer_version`, clear entries), `INDEX RECONCILE` (remove entries
  not in the caller-supplied authoritative id set), and `INDEX DESTROY`
  (zeroize the key and delete the index, name reusable).
- **E2EE BLIND mode** — `PUT` and `SEARCH` accept a `BLIND` flag. In BLIND
  mode the client submits a base64-encoded `BlindTokenSet` JSON produced by
  `shroudb-veil-blind`; the server stores/compares directly without seeing
  plaintext or the client's key.
- **TOKENIZE command** — returns blind tokens for the given plaintext without
  storing, for callers that want to pre-compute wire payloads or integrate
  with external systems.
- **Bounded index size** — `VeilConfig.max_entries_per_index` rejects new
  entries past the cap (updates to existing entries still succeed); `0`
  means unlimited.
- **Per-index HMAC key** — each `BlindIndex` holds a fresh random key;
  `INDEX ROTATE` and `INDEX DESTROY` both destroy key material. Keys never
  leave the server in standard mode.
- **Connection protocol** — standard ShrouDB connection-management commands
  exposed alongside the Veil-specific ones: `HELLO` (engine identity
  handshake, pre-auth), `AUTH <token>` (token-based connection auth),
  `PING`, `HEALTH`, and `COMMAND LIST`.

## Engine dependencies

### Dependency: chronicle

Veil's workspace pins `shroudb-chronicle-core` (1.11.0). `VeilEngine` accepts
a `Capability<Arc<dyn ChronicleOps>>` slot (from `shroudb-server-bootstrap`)
and emits audit `Event` records tagged `AuditEngine::Veil` from
`index_create`, `put`, `search`, and the other mutating operations via
`emit_audit_event`.

**Explicit capability slots, no silent None.** `policy_evaluator` and
`chronicle` on `VeilEngine::new` are both `Capability<T>`, which the server
binary must resolve from explicit `[audit]` and `[policy]` config sections —
each section requires a `mode` of `"remote"`, `"embedded"`, or `"disabled"`,
and `"disabled"` requires a named `justification`. Absence of a config
section is a startup error, not a silent no-op. Tests use
`Capability::DisabledForTests`; production disables go through
`Capability::DisabledWithJustification("<reason>")`.

**What breaks when disabled.** If `chronicle` resolves to `Disabled*`,
`emit_audit_event` returns `Ok(())` without recording: indexing, tokenization,
and search run to completion with no audit trail. The justification is
visible in config, which is the audit surface. Debt test
`debt_4_engine_must_reject_missing_chronicle_in_enforcing_mode` tracks a
separate knob — a `VeilConfig::require_audit` flag that would fail engine
construction when Chronicle is absent regardless of justification — which
is still open work.

**What works when enabled.** When Chronicle is wired and reachable, every
index-management op (`INDEX_CREATE`, `INDEX_ROTATE`, `INDEX_DESTROY`,
`INDEX_REINDEX`), `PUT`, `DELETE`, and `RECONCILE` call records an `Event`
with operation name, `"index"` resource type, the index name, `EventResult`,
actor id, and elapsed `duration_ms`. Chronicle failures are fatal for
mutating operations: if the sink is configured but unreachable,
`emit_audit_event` returns `VeilError::Internal("audit failed: ...")` and
the caller sees the operation fail closed. **SEARCH is a known exception**:
`engine.rs` still uses `let _ = self.emit_audit_event("SEARCH", ...)`, which
swallows Chronicle failures and returns hits un-audited. Debt test
`debt_3_search_must_fail_closed_when_chronicle_unreachable` captures this as
open work.

**Actor identity is not yet wired.** Every `emit_audit_event` call and every
`check_policy` call passes `actor = None`, so audit events record
`"anonymous"` and policy requests carry an empty principal id. Debt tests
`debt_1_put_must_forward_actor_identity_to_sentry` and
`debt_2_audit_event_must_record_real_actor_not_anonymous` capture this;
the fix requires threading actor identity through the engine signature.

**Other open debt.** `debt_5_search_score_thresholds_must_be_configurable`
captures the hardcoded prefix/fuzzy score thresholds in `search.rs` (0.6
and 0.3) — they should live on `VeilConfig`. `debt_6_blind_put_must_reject_
non_hex_tokens` captures that `PUT ... BLIND` currently accepts arbitrary
strings in `BlindTokenSet` without verifying they are hex-encoded
HMAC-SHA256 output, which lets a malicious client poison an E2EE index
with garbage tokens. Full list: `cargo test -p shroudb-veil-engine debt_`.

## Reverse dependencies

- **shroudb-sigil** — per the release DAG, Sigil is the first engine to
  migrate and consumes Veil for searchable encrypted user fields. When a
  Sigil record declares `pii: true` with `searchable: true`, Sigil calls
  Veil to generate blind indexes on write and search them at query time.
- **shroudb-moat** — embeds both `shroudb-veil-engine` and
  `shroudb-veil-protocol` to expose Veil behind the single-binary Moat hub.
- **shroudb-codegen** — reads `protocol.toml` to generate client bindings;
  it consumes the schema, not the crates.
- **shroudb-veil-client** — the Rust SDK used by the CLI and by downstream
  applications integrating over the wire.

### What `shroudb-veil-blind` exposes (the Sigil integration surface)

`shroudb-veil-blind` is deliberately minimal: it is the client-side half of
the tokenizer contract and has no dependency on the engine, store, or wire
crates, which lets Sigil (or any ShrouDB SDK) embed it cheaply.

- `BlindKey` — 32-byte zeroizing HMAC key with `from_bytes`, `generate`
  (CSPRNG via `ring`), `derive` (HKDF-SHA256 for shared-secret derivation),
  and `as_bytes`.
- `BlindTokenSet { words, trigrams }` — wire-compatible with the server-side
  type; `Serialize`/`Deserialize` via serde.
- `tokenize_and_blind(key, plaintext)` — tokenize with the
  `shroudb-veil-core` tokenizer and HMAC each token with the caller's key.
- `tokenize_and_blind_field(key, data, Option<field>)` — JSON field
  extraction plus tokenize-and-blind, mirroring the engine's `FIELD` option.
- `blind_tokens(key, &TokenSet)` — blind a pre-computed `TokenSet` (useful
  when the caller inspects raw tokens before blinding).
- `encode_for_wire` / `decode_from_wire` — base64+JSON codec matching
  `PUT ... BLIND` / `SEARCH ... BLIND` wire format.
- `TOKENIZER_VERSION` — re-exported from `shroudb-veil-core::tokenizer` so
  clients can pin their blind tokens to a specific tokenizer version.
- `BlindError` — error enum covering key length, key generation, and
  serialization failures.

## Deployment modes

- **Standalone TCP server.** `shroudb-veil-server` builds the `shroudb-veil`
  binary (default workspace member). It composes `shroudb-veil-engine`,
  `shroudb-veil-protocol`, `shroudb-storage`, `shroudb-server-tcp`, and
  `shroudb-server-bootstrap`, listens on `default_tcp_port = 6799`, speaks
  RESP3 over TCP, and optionally exposes the REST-style HTTP API from
  `protocol.toml` (`/index/create`, `/put`, `/search`, `/tokenize`,
  `/health`, etc.) when `server.http_bind` / `--http-bind` /
  `VEIL_HTTP_BIND` is set. The config file must declare `[audit]` and
  `[policy]` sections; each resolves to a `Capability<T>` slot that is
  passed to `VeilEngine::new`. A deploy that genuinely does not want an
  audit sink or policy evaluator must set `mode = "disabled"` and provide
  a `justification` — silent `None` is not accepted.
- **Embedded in Moat.** Moat pulls in `shroudb-veil-engine` and
  `shroudb-veil-protocol` directly, sharing the same process and storage
  layer as the other ShrouDB engines. Because `VeilEngine` is generic over
  `Store`, the same engine code runs unchanged whether the `Store` is an
  embedded storage handle or a remote client to a separate ShrouDB server.
- **Embedded as a library.** Other engines (Sigil) depend on
  `shroudb-veil-engine` directly via the `VeilOps` capability trait surface
  to generate and query blind indexes in-process. Pure clients that only
  need to produce wire payloads depend on `shroudb-veil-blind` alone — no
  storage, no async runtime, and optional WASM support via the `wasm`
  feature.
