# TODOS

## Debt

Each item below is captured as a FAILING test in this repo. The test is the forcing function — this file only indexes them. When a test goes green, check its item off or delete the entry.

Rules:
- Do NOT `#[ignore]` a debt test to make CI pass.
- A visible ratchet (`#[ignore = "DEBT-X: <reason>"]`) requires a matching line in this file AND a clear reason on the attribute. Use sparingly.
- `cargo test -p shroudb-veil-engine debt_` is the live punch list.

### Cross-cutting root causes

1. **Server binary hardcodes `None` for Sentry & Chronicle.** `main.rs:107` builds `VeilEngine::new(store, veil_config, None, None)`; no config surface.
2. **Every engine op hardcodes `None` for actor.** `engine.rs:207,221,235,259,331,411,518` — same Sigil-shape gap.
3. **SEARCH silently swallows audit failures.** `engine.rs:549` uses `let _ = ... emit_audit_event("SEARCH", …)` — inconsistent with every other op which propagates.

### Open

- [x] **DEBT-1** — PUT must forward caller actor identity to Sentry. Test: `debt_1_put_must_forward_actor_identity_to_sentry` @ `shroudb-veil-engine/src/engine.rs`.
- [x] **DEBT-2** — audit must record real actor, not `"anonymous"` sentinel. Test: `debt_2_audit_event_must_record_real_actor_not_anonymous` @ same file.
- [x] **DEBT-3** — SEARCH must fail-closed when Chronicle is unreachable (parity with other ops). Test: `debt_3_search_must_fail_closed_when_chronicle_unreachable` @ same file.
- [x] **DEBT-4** — engine must reject missing Chronicle in enforcing mode. Test: `debt_4_engine_must_reject_missing_chronicle_in_enforcing_mode` @ same file.
- [x] **DEBT-5** — search prefix/fuzzy score thresholds must be configurable (currently hardcoded 0.6 / 0.3 in `search.rs:23,24`). Test: `debt_5_search_score_thresholds_must_be_configurable` @ same file.
- [x] **DEBT-6** — blind-PUT must reject non-hex tokens (currently accepts garbage; attacker can poison an E2EE index). Test: `debt_6_blind_put_must_reject_non_hex_tokens` @ same file.
- [ ] **F-veil-7 (L)** — `index_manager.rs:536,552` silently swallows posting-list errors. *No debt test yet; add one before fixing.*
