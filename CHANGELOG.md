# Changelog

All notable changes to ShrouDB Veil are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [v1.5.1] - 2026-04-09

- Version bump release

## [v1.5.0] - 2026-04-09

### Added

- add tokenizer version tracking and reindex/reconcile commands
- adapt to chronicle-core 1.3.0 event model

## [v1.4.2] - 2026-04-04

### Changed

- use shared ServerAuthConfig from shroudb-acl

### Other

- docs: add BLIND keyword and E2EE workflow to documentation

## [v1.4.0] - 2026-04-03

### Added

- add BLIND keyword for E2EE client-side encryption and tokenization

## [v1.3.3] - 2026-04-02

### Fixed

- use entrypoint script to fix volume mount permissions

### Other

- Add proptest fuzz tests for Veil index name validation
- Add configurable max_entries_per_index to prevent index DoS

## [v1.3.2] - 2026-04-01

### Other

- Use check_dispatch_acl for consistent ACL error formatting

## [v1.3.1] - 2026-04-01

### Other

- Add concurrent/failure/expansion tests from ENGINE_REVIEW_v6

## [v1.3.0] - 2026-04-01

### Other

- Add PolicyEvaluator for ABAC, migrate TCP to shared crate

## [v1.2.10] - 2026-04-01

### Other

- Wire shroudb-server-bootstrap, eliminate startup boilerplate
- Add storage corruption recovery test

## [v1.2.9] - 2026-04-01

### Other

- Migrate client to shroudb-client-common, eliminate ~63 lines of duplication

## [v1.2.8] - 2026-04-01

### Other

- Add null byte handling test for tokenizer

## [v1.2.7] - 2026-04-01

### Other

- Add orphan reconciliation for blind index cleanup

## [v1.2.6] - 2026-04-01

### Other

- Fail-closed audit for security-critical operations
- Add AGENTS.md

## [v1.2.5] - 2026-04-01

### Other

- Migrate TCP handler to shroudb-server-tcp, eliminate ~165 lines of duplication (v1.2.5)

## [v1.2.4] - 2026-03-31

### Other

- Optimize search: bounded BinaryHeap, cached entry counts (v1.2.4)

## [v1.2.3] - 2026-03-31

### Other

- Add unit tests to veil-core: tokenizer, matching, index validation (v1.2.3)

## [v1.2.2] - 2026-03-31

### Other

- Add edge case tests: empty query, invalid UTF-8, max-length entry, SecretBytes key material (v1.2.2)

## [v1.2.1] - 2026-03-31

### Other

- Arc-wrap blind indexes in cache to avoid cloning on lookup (v1.2.1)
- Return SecretBytes from generate_key_material, not bare Vec<u8>

## [v1.2.0] - 2026-03-31

### Other

- Wire ChronicleOps audit events into Veil engine (v1.2.0)

## [v1.1.2] - 2026-03-31

### Other

- Add ACL unit tests to protocol dispatch (v1.1.2)

## [v1.1.1] - 2026-03-31

### Other

- Harden server: expect context on unwraps (v1.1.1)
- Harden Veil v1.1.0: key zeroization, search early-exit, dedup

## [v1.0.0] - 2026-03-29

### Other

- Veil v1: blind index engine with HMAC-SHA256 token derivation

## [v0.1.1] - 2026-03-27

### Other

- v0.1.1 — integration tests, fuzzy search fix, PING, COMMAND LIST

## [v0.1.0] - 2026-03-27

### Other

- Remove local patch overrides, regenerate Cargo.lock
- Clean v0.1.0 release — all deps on private registry
- Migrate from git deps to private crate registry for v0.1.0 release
- Remove tag trigger from CI — release workflow handles tags
- Standardize release workflow using reusable rust-release.yml
- Add security posture requirements to CLAUDE.md
- Split CI and release workflows, switch to self-hosted runners
- Update README: add CONFIG commands, note RESP3 support
- Add CONFIG GET/SET/LIST commands to Veil protocol
- Add RESP3 wire protocol support to shroudb-veil-protocol
- Add Dockerfile, Docker Hub README, and full release CI
- Fix dead_code warnings in remote-only build
- Initial ShrouDB Veil implementation

