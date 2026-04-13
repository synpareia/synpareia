# Changelog

All notable changes to the synpareia SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
