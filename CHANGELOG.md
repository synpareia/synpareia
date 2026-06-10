# Changelog

All notable changes to the synpareia SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-06-10

Launch-hardening release driven by the 2026-06-10 fresh-eyes audit (defect IDs
D-1, D-7, D-8). Minor bump under the pre-1.0 SemVer caveat: two behaviour
changes below are breaking for callers who relied on fail-open or
RFC-violating output — both are documented under **Breaking** with migration
notes. Also ships the new (experimental) `synpareia.topology` module.

> **Upgrading from 0.5.0?** The 0.5.1 entry below also applies to you:
> 0.5.1 was documented and version-bumped but **never published to PyPI**
> (the published sequence is 0.5.0 → 0.6.0), so its PT-001/002/003
> hardening first ships in this release.

### Breaking

- **`verify_block` now fails closed when an author key is supplied (D-1).**
  Previously a block with `signature is None` returned `True` from
  `verify_block(block, author_public_key)` — only the content hash was
  checked, so a signature-stripped block still "verified" as authored. New
  semantics: when `author_public_key` is supplied, the block MUST carry a
  primary signature that verifies against that key; an unsigned block does
  not verify. **Migration:** callers that relied on unsigned blocks passing
  an authored-verification call must either (a) sign the blocks, or (b) pass
  `author_public_key=None` to request an explicit structure-only check
  (content hash + co-signatures when a mapping is passed) — that path is
  unchanged. No transitional `DeprecationWarning` release: the fail-open
  behaviour was a security defect (the sibling of the `verify_chain`
  fail-open bug fixed earlier), and a warning-but-still-passing release
  would have preserved the vulnerability. Regression tests cover stripped
  signatures, never-signed blocks, structure-only mode, and co-signatures
  not compensating for a stripped primary.
- **Integers outside ±2^53 in canonicalized content now raise `ValueError`
  per RFC 8785 (previously produced RFC-violating output).** The old
  home-rolled canonicalizer serialized large ints via `str()`, emitting
  bytes that violate RFC 8785's number rules (so third-party JCS
  implementations could not reproduce our hashes). The new `rfc8785`-backed
  implementation raises `rfc8785.IntegerDomainError` (a `ValueError`
  subclass). **Migration:** use string timestamps (e.g. ISO 8601) or
  millisecond-precision integer timestamps; any integer with magnitude
  below 2^53 is unaffected.

### Added

- **Floats now canonicalize** per RFC 8785 / ECMAScript shortest round-trip
  serialization: `{"confidence": 0.7}` is now signable. Previously any float
  raised a hard `TypeError` (which bit the Witnessed-Prediction Form).
  End-to-end sign+verify regression added.
- **`synpareia.topology`** — experimental v0 (in-memory) topology layer:
  pairwise directional edges between DIDs. Public surface: `EdgePair`,
  `TopologyStore`, `shortest_path`, `path_familiarity`, `path_strength`,
  per-channel accumulators, the tag→channel-delta mapper, the contribution
  ledger (erasure support), and the anchored transitive reputation aggregate
  (`aggregate_reputation`, bounded-hop path discount, precision-weighted
  combine) with visibility-class bucketing. Production substrate (directory
  DB integration, witness hooks, MCP exposure) lands as separate work; treat
  this module's API as unstable until then. **No network read surface serves
  these aggregates anywhere today** — this is library code you can run on
  your own data, not a hosted reputation feed. One known design gap shipped
  as-is (tracked, pre-consumer): the transitive *familiarity* walk in
  `transitive_author_weights` is not yet visibility-filtered (only valence
  opinions are), so a served aggregate could leak the existence/strength of
  bilateral edges through reachability effects. Do **not** build a serving
  surface on this module until that is resolved (audit D-11; the resolution
  gates any consumer).

### Changed

- **Canonicalization is now backed by the `rfc8785` library** (Trail of
  Bits, Apache-2.0, py.typed) instead of the home-rolled implementation in
  `synpareia.hash` (D-8). `jcs_canonicalize` remains as a thin wrapper, so
  call sites don't churn. **Hash compatibility:** a hypothesis differential
  suite runs the old implementation (kept verbatim in the test module as the
  oracle) against the new one over the old code's accepted domain — output
  is byte-identical for str/int/bool/None/list/dict with safe-range ints and
  BMP keys, so every existing chain, seal, and signature verifies unchanged.
- **Supplementary-plane dict keys now sort in UTF-16 code-unit order** as
  RFC 8785 requires (previously code-point order — RFC drift). Only affects
  keys containing characters above U+FFFF. Consequence for pre-0.6.0
  artifacts: a signature or hash produced by the old implementation over
  content whose dict keys mix supplementary-plane characters will fail
  verification under 0.6.0 (fail-closed, never silently different) — if you
  hold such artifacts (none are known to exist in the ecosystem), re-sign
  under 0.6.0.

### Fixed

- **README quickstart repaired (D-7):** every code block now runs
  top-to-bottom in a clean venv.

### Notes

- New runtime dependency: `rfc8785>=0.1.4` (Apache-2.0).
- **Honesty note on witness identity binding (audit D-9):** the witness
  service does not verify the `requester_id` (or challenge `target_id`)
  strings sent with blind conclusions and liveness challenges — identity
  binding is the caller's self-asserted claim in v1, until Phase-2 anonymous
  credentials land. The `synpareia.witness.client` docstrings now say so
  explicitly. Existing behaviour is unchanged; this is a documentation
  truth-pass.

## [0.5.1] - 2026-05-06 — never published to PyPI; first ships in 0.6.0

Defence-in-depth tightening of `synpareia.profile.client` and `synpareia.auth.rfc9421` based on the three LOW pentest findings (PT-001/002/003) deferred from the 0.5.0 publish gate. Behaviour-preserving for callers who already pass canonical inputs; fail-fast for callers who don't. Patch release.

### Changed

- **`ProfileClient.publish` cross-checks identity bindings (PT-001).** Raises `ValueError` if `did` is not canonical, if `did` doesn't equal `"did:synpareia:" + sha256(public_key).hex()`, or if the embedded `id` field in `signed_bytes` (when JSON-parseable) disagrees with `did`. The server-side validator remains the real gate; the SDK now refuses to dispatch a request that's guaranteed to be rejected.
- **`ProfileClient.{publish, get_existence, get_history, get_well_known, delete_history_version, delete_profile}` validate the `did` argument (PT-002).** Each method checks `did` against `^did:synpareia:[0-9a-f]{64}$` before f-string-interpolating into the URL path. Eliminates the `../`-traversal class via the `did` parameter at the SDK boundary.
- **`sign_request` mints a 128-bit random nonce by default (PT-003).** When `nonce=None`, the wrapper now generates `secrets.token_hex(16)` rather than signing without a nonce. Replay defence is on-by-default rather than opt-in. Callers that need deterministic nonces (tests, content-addressed signatures) can still pass an explicit `nonce` argument. An explicit empty/whitespace `nonce` is rejected with `ValueError` rather than silently producing a signature that `verify_request(require_nonce=True)` will reject as missing.
- **`verify_request` adds `require_nonce: bool = True` (PT-003).** Default rejects signatures whose `Signature-Input` parameters omit `nonce` with a structured `missing_nonce` error code. The Phase 1d profile router already enforces nonce-tracking on top of `verify_request`; the new default propagates the same expectation to ad-hoc users. Set `False` only when the caller has its own replay defence.

### Notes

- No public-API removals; all changes are additive defaults or stricter validation on existing entry points. Downstream callers that already pass canonical DIDs and matching public keys are unaffected.
- Adversarial registry entries `ADV-063` / `ADV-064` / `ADV-065` track the regression tests for these findings.
- The `tag="synpareia"` signature label and JCS canonicalisation are unchanged.

## [0.5.0] - 2026-05-06

RFC 9421 HTTP Message Signatures + the `synpareia.profile` module for publishing and fetching agent cards on the directory. Phase 1a + Phase 1f of the funnel-implementation-roadmap.

### Added

- **`synpareia.auth.rfc9421`** — Ed25519 sign/verify wrapper over `http-message-signatures`. `sign_request(method, target_uri, body, private_key, keyid, ...)` returns the canonical `Signature-Input` / `Signature` / `Content-Digest` headers with `tag="synpareia"` for domain separation. `verify_request(...)` returns `(valid, [SignatureVerifyError])` with structured codes (`missing_signature` / `unknown_keyid` / `content_digest_mismatch` / `expired` / `signature_invalid` / `wrong_algorithm` / `malformed_signature`). Default-covered components are `("@method", "@target-uri", "content-digest")`. Header lookups are case-insensitive (Starlette / FastAPI lowercase inbound headers; the wrapper canonicalises them before the upstream library checks for `Signature-Input` etc.).
- **`synpareia.profile`** — consumer-side surface for the directory's `/api/v2/profiles` and `/agents/{did}/.well-known/agent-card.json` routes. Local helpers (no network):
  - `build_agent_card(profile, **fields) -> AgentCard` — assembles a card from a `synpareia.identity.Profile` plus optional A2A and synpareia-extension fields. Derives the DID from `profile.public_key` and refuses inconsistent Profile inputs (DID-binding enforcement).
  - `card_canonical_bytes(card) -> bytes` — JCS canonicalisation; the bytes operators sign and the directory verifies.
  - `sign_agent_card(card_bytes, private_key) -> bytes` — Ed25519 signature.
  - `verify_agent_card(card_bytes, signature, public_key) -> bool` — offline verification.
- **AgentCard wire shape** as plain frozen dataclasses (no pydantic dependency in the SDK; the directory validates on publish): `AgentCard`, `SynpareiaExtensions`, `FirstContactFee`, `PersistenceOptIn`, `WellKnownPublicationPolicy`, `A2ACapabilities`, `A2AAuthentication`. Same JSON wire shape as the main service's pydantic schema. `WellKnownPublicationPolicy()` is the explicit opt-out (empty list); omit the policy block entirely to get default visibility (`name`/`description`/`version`).
- **`ProfileClient` / `SyncProfileClient`** (`synpareia[profile]` extra; httpx-backed) — async + sync directory clients. Methods: `publish` (POST envelope + RFC 9421 sigauth), `get_existence` (fixed-shape view), `get_history` (cursor-paginated), `get_well_known` (A2A discovery surface), `delete_history_version` (sigauth'd tombstone), `delete_profile` (sigauth'd full delete), `request_witness_anchor` (hash-only timestamp seal — witness never sees the DID, the card content, or any operator identifier). Sigauth flows through `synpareia.auth.rfc9421.sign_request`.

### Notes

- **Pydantic-free SDK.** The dataclasses' `to_dict()` produces the same JSON the main-service pydantic `AgentCard` accepts on publish. Consumers don't need pydantic; the directory does its own validation.
- **Witness anchoring is hash-only by construction.** `ProfileClient.request_witness_anchor` sends only `SHA-256(signed_card_bytes)` to `/api/v1/seals/timestamp`. The hash-only contract is regression-tested.
- **Deps:** new transitive deps `http-message-signatures>=2.0` (Apache-2.0) for sigauth and `httpx>=0.27` (BSD-3-Clause; already a dep of the `witness` extra) for the network client. Both audited via `pip-audit` — no known vulnerabilities.

## [0.4.0] - 2026-05-05 — never published to PyPI; first shipped in 0.5.0

KEY_ROTATION block — track which Ed25519 key currently controls a DID over time.
Phase 0.2 of the funnel-implementation-roadmap; the last item closing out Phase 0.

### Added

- **`BlockType.KEY_ROTATION`** — new block type declaring a transition in the active controlling key for a DID.
- **`synpareia.policy.key_rotation`** module:
  - `KeyRotationPayload` dataclass — typed handle for the structured rotation payload (`did`, `old_key`, `new_key`, `rotated_at`).
  - `create_key_rotation_block(profile, *, new_public_key)` — mints a KEY_ROTATION block signed by the old private key. Rejects no-op rotations (new key identical to old) and wrong-length keys. Profile must hold the current private key.
  - `parse_key_rotation_payload(block) -> KeyRotationPayload | None` — decodes the payload and rejects malformed JSON, wrong `kind`, malformed base64, wrong key length, unparseable timestamps.
  - `verify_key_rotation_block(block, *, expected_old_key) -> (bool, errors)` — single-block validation; checks payload shape, old-key match, signature against expected_old_key, no-op rejection.
  - `resolve_did_key(chain, did, *, initial_key) -> bytes | None` — walks the chain forward from a known starting key, applies each KEY_ROTATION authored by the DID, returns the current controlling key. Returns `None` on any signature mismatch or payload break (fail-closed).
- All five names re-exported from the top-level `synpareia` namespace.

### Notes

- The synpareia DID is permanent — derived from the *original* public key (`did = "did:synpareia:" + sha256(original_pk).hex()`). KEY_ROTATION blocks track who *currently controls* signing rights for that DID; the DID itself doesn't change.
- v1 KEY_ROTATION blocks are signed only by the old key. The new key's first valid use after the rotation is implicit consent — no co-signature requirement. Callers wanting stronger acknowledgement can layer a BlockProposal envelope.
- **Key-loss is intentionally terminal under v1.** Without the old private key, no valid KEY_ROTATION block can be minted; there is no v1-defined recovery path. M-of-N social recovery, witness-attested re-attestation, etc. are out of scope. See `docs/explorations/chain-policy-primitive.md` §7 for the long-term recovery strategy.
- Per the roadmap's `simplicity-NC2` note: no key has actually been rotated pre-launch. KEY_ROTATION ships now to lock in the design surface and unblock Phase 1's signature-auth model under the rotation chain — but the lifecycle path doesn't actually run until post-launch. 24 unit tests cover the protocol; first real exercise will be a launch-week dojo scenario.

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
