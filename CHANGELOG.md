# Changelog

All notable changes to the synpareia SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-04-21

Chain policy primitive, multi-party negotiation, threshold commitments, and witness ephemeral attestations. Two red-team passes with all CRITICAL/HIGH findings fixed. Pre-publish gate close-read (2026-04-30) added: `SyncWitnessClient` deprecation fix (E9), `AmendmentRules` serialization made path-collision-safe, `from_public_key` validates 32-byte input.

### Added

- **Chain policy primitive** — `synpareia.policy` module with `Policy`, `PolicyBuilder`, per-block rules, lifecycle state machine (PROPOSED → PENDING → ACTIVE → CONCLUDED), and template factories (`templates.cop`, `templates.sphere`, `templates.audit`, `templates.custom`). Every chain has a POLICY block at position 1 whose `content_hash` equals `chain.policy_hash`.
- **Lifecycle payloads** — `BlockType.ACCEPTANCE`, `BlockType.ACK`, `BlockType.AMENDMENT`, `BlockType.CONCLUSION` with JCS-canonical payload builders (`acceptance_bytes`, `ack_bytes`, `conclusion_bytes`) that bind `chain_id` to prevent cross-chain replay.
- **Block proposals** — `synpareia.proposal` module with `BlockProposal` dataclass, `start_proposal`, `sign_proposal`, `verify_proposal`, `assemble_block`. Multi-party co-signing with envelope-bound cosigner set.
- **Threshold commitments** — `synpareia.threshold` module with `xor_shares`, `random_shares`, `create_threshold_commitment`, `verify_threshold_commitment` realising n-of-n XOR assembly (S5 regime 2). Neither party can unilaterally open.
- **Witness ephemeral attestations** — `synpareia.witness.ephemeral` module with typed `LivenessRelayAttestation`, `VerifyAttestation`, `ArbitrationAttestation`, `RandomnessAttestation`, `QueryAttestation`, `FairExchangeAttestation` — offline-verifiable, stateless server side.
- `verify_chain_policy(chain, *, public_keys=None)` — standalone validator wired into `chain.verify()`.
- `verify_chain_structure(chain)` — opt-in structural-only check that skips signature verification.
- `verify_export_structure(export)` — opt-in structural-only export verification.

### Changed

- **Breaking:** `create_chain(owner)` → `create_chain(owner, *, policy=...)`. Use `templates.cop(owner)` for a single-signer chain-of-presence.
- **Breaking:** `verify_chain(chain)` now fails closed on signatures when `public_keys` is not provided. Use `verify_chain_structure(chain)` for the old structural-only behavior. (Phase D+ F1.)
- **Breaking:** `verify_export(export)` now fails closed on signatures when `public_keys` is not provided. Use `verify_export_structure(export)` for the old structural-only behavior.
- **Breaking:** `WitnessClient.timestamp_seal(block_hash)` and `WitnessClient.state_seal(chain_id, chain_head)` dropped the `requester_id` positional (carries over from 0.2.0 sparse-witness surgery — unreleased until now).
- **Breaking (semantic):** Sparse-witness construction — the public seal request paths (`/seals/timestamp`, `/seals/state`) no longer persist or attribute `requester_id`. A seal row now stores only `{hash, witness_signature, sealed_at}`. The attestation remains cryptographically sound; the witness simply no longer knows who asked. Callers that relied on the old behavior to recover provenance from seals must now track that mapping themselves. Ratifies Position 4 of `docs/explorations/counterparty-reputation-legal.md`.
- `_signing_envelope` now binds `metadata_hash` and `cosigners_hash` so post-signing tamper invalidates the primary signature.

### Fixed (2026-04-30 close-read pass)

- **E9 (HIGH):** `SyncWitnessClient` no longer uses deprecated `asyncio.get_event_loop()` (8 sites) — now uses `asyncio.run()`. Avoids `DeprecationWarning` on Python 3.12 and the `get_event_loop` removal in Python 3.14.
- **AmendmentRules serialization (MEDIUM):** an override whose path is literally `"default"` no longer collides with the rule's own `default` field on round-trip. Overrides are now nested under an `overrides` sub-key. Pre-0.3.0 flat shape still reads for backward compatibility (no migration needed).
- **`from_public_key` validation (LOW):** explicitly rejects non-32-byte input early rather than deferring failure to first signature-verify.

### Security

- Two red-team passes (Phase D+ and Phase F) with all CRITICAL/HIGH findings fixed and regression-tested:
  - **R1/ADV-033** (CRITICAL): `export_chain` / `_import_chain` round-trip `co_signatures` — strip-to-demote attack blocked.
  - **R2/ADV-034** (CRITICAL): lifecycle payloads bind `chain_id` — cross-chain replay blocked.
  - **R3/ADV-035** (HIGH): unsigned lifecycle-transition blocks unconditionally rejected.
  - **R4/ADV-036** (HIGH): `verify_chain_policy` forwards `cosigner_public_keys`.
  - **R5/ADV-037** (HIGH): `verify_export` fails closed on signatures.
  - **R7/ADV-039** (MEDIUM): `verify_chain_policy` enforces `SUPPORTED_POLICY_VERSIONS = {"1"}`.
  - **F1-F7** (Phase D+): envelope bindings for metadata and cosigners, `BlockProposal.__post_init__` identity check, threshold footgun rejections.
- 334 passing tests; `sdk/src/` fully mypy-clean (strict mode).

### Removed

- Dead `synpareia.signing.sign_block` helper (R8/ADV-040). Use `create_block` with JCS-canonical signing envelope via `block._signing_envelope`.

## [0.2.0] - 2026-04-16

Tier 4 — witness client, seal verification, offline attestations.

### Added

- **Seals** — `TimestampSeal`, `StateSeal` dataclasses with `.verify(witness_public_key) -> bool` for offline verification.
- **Witness client** — `WitnessClient` (async) and `SyncWitnessClient` (sync) with `timestamp_seal`, `state_seal`, request methods and blind-conclusion support.
- Fresh-agent scenarios in `tests/scenarios/` covering Tier 1-4 integration.

## [0.1.0] - 2026-04-12

Initial release. Tiers 1-3: core primitives for agent identity, attestation, and cross-chain references.

### Added

- **Identity** — Ed25519 keypair generation, DID derivation (`did:synpareia:<hash>`), profile serialization
- **Blocks** — Typed, hashable, signed atomic records with full/hash-only/revealed content modes
- **Chains** — Append-only, hash-linked sequences with position tracking and integrity verification
- **Anchors** — Cross-chain references (correspondence, receipt, bridge, branch) with independent verification
- **Commitments** — Commit-reveal scheme with length-prefixed payloads and constant-time verification
- **Hashing** — SHA-256 content hashing, JCS (RFC 8785) canonicalization
- **Signing** — Ed25519 block signing with JCS-canonicalized signing envelopes
- **Storage** — `MemoryStore` default backend, `ChainStore` protocol for custom backends
- **Export** — Portable chain export/import with standalone verification
- 13 standard block types: message, thought, reaction, edit, retraction, join, leave, system, commitment, anchor, seal, state, media
