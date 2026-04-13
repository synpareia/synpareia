# synpareia

Cryptographic primitives for AI agent identity, attestation, and interaction verification.

Synpareia gives AI agents a persistent, verifiable identity and a tamper-evident history of their interactions. It works locally with zero network dependencies, zero accounts, and a single `pip install`.

## Install

```bash
pip install synpareia
```

Requires Python 3.11+. Only dependency: `cryptography`.

## Quick Start

### Create an identity

Every agent gets an Ed25519 keypair. The identity is derived deterministically from the public key — no server, no registration.

```python
import synpareia

# Generate a new agent identity
profile = synpareia.generate()
print(profile.id)  # did:synpareia:a1b2c3...
```

### Sign a block

A block is the atomic unit: a typed, hashed, signed record of something that happened.

```python
block = synpareia.create_block(
    profile,
    type="message",
    content="Hello from Agent A",
)

# Anyone with the public key can verify authorship
assert synpareia.verify_block(block, profile.public_key)
```

### Build a chain

A chain is an ordered, hash-linked sequence of blocks — a tamper-evident history.

```python
# Create a Chain of Presence (personal history)
chain = synpareia.create_chain(profile)

# Append blocks
pos1 = synpareia.append_block(chain, block)
pos2 = synpareia.append_block(chain, another_block)

# Verify the chain is intact
valid, errors = synpareia.verify_chain(chain)
assert valid
```

### Export and verify independently

Chains are portable. Export them as JSON, send them to anyone, and they can verify independently.

```python
from synpareia import export_chain, verify_export

# Export
data = export_chain(chain)

# Anyone can verify — no network, no trust, just math
valid, errors = verify_export(data)
assert valid
```

### Link chains with anchors

When an agent participates in a shared conversation, anchors link their personal chain to the shared record.

```python
# Agent A's personal chain references a position in the shared chain
anchor_block, anchor_pos = synpareia.create_anchor_block(
    profile,
    agent_chain,
    target_chain_id=shared_chain.id,
    target_sequence=3,
    target_block_hash=shared_block.content_hash,
    anchor_type="correspondence",
)
```

### Commit-reveal for independent evaluation

Two agents can independently commit to assessments before revealing them — proving neither was influenced by the other.

```python
# Agent commits (keeps nonce secret)
commitment_block, nonce = synpareia.create_commitment_block(
    profile,
    content=b"My honest assessment: excellent interaction",
)

# Later, reveal and verify (the commitment hash is the block's content)
assert synpareia.verify_commitment(
    commitment_block.content,
    b"My honest assessment: excellent interaction",
    nonce,
)
```

## Core Concepts

### Four Primitives

| Primitive | Purpose | Example |
|-----------|---------|---------|
| **Block** | Atomic signed record | A message, thought, reaction, or system event |
| **Chain** | Ordered, hash-linked sequence of blocks | An agent's personal history, a conversation log |
| **Anchor** | Cross-chain reference | "This block in my chain corresponds to that block in theirs" |
| **Seal** | Third-party attestation (Tier 4, coming soon) | A witness timestamps or checkpoints a chain |

### Chain of Presence (CoP)

An agent's personal, append-only, hash-linked history across interactions and platforms. Like a cryptographic resume — verifiable by anyone, controlled by the agent.

### Spheres

When two or more agents interact, the shared observable history is a sphere chain. Each agent's CoP links to the sphere via anchors, creating a verifiable record of who said what, and when.

## What You Can Verify

| Claim | How |
|-------|-----|
| "Agent X authored this content" | Ed25519 signature on the block |
| "This content existed at time T" | Block timestamp + chain position |
| "This history hasn't been tampered with" | Hash-linked chain verification |
| "Agent X participated in conversation Y" | Anchor from CoP to sphere chain |
| "Both assessments were independent" | Commit-reveal: both commitments precede both reveals |
| "This chain export is authentic" | `verify_export()` — standalone, offline verification |

## API Reference

### Identity

| Function | Description |
|----------|-------------|
| `generate()` | Create a new Ed25519 keypair and Profile |
| `from_private_key(bytes)` | Reconstruct Profile from private key |
| `from_public_key(bytes)` | Create a verify-only Profile |
| `load(pub_b64, priv_b64?)` | Load Profile from base64-encoded keys |

### Blocks

| Function | Description |
|----------|-------------|
| `create_block(profile, type, content)` | Create a signed block |
| `verify_block(block, public_key?)` | Verify content hash and signature |
| `reveal_block(block, content)` | Reveal content of a hash-only block |

### Chains

| Function | Description |
|----------|-------------|
| `create_chain(profile, chain_type?)` | Create a new chain |
| `append_block(chain, block)` | Append a block, returns ChainPosition |
| `verify_chain(chain)` | Walk and verify all hash links |
| `export_chain(chain)` | Export as portable, verifiable JSON |
| `verify_export(data)` | Verify an export without the original chain |

### Anchors

| Function | Description |
|----------|-------------|
| `create_anchor_block(profile, chain, ...)` | Create a cross-chain reference |
| `verify_anchor(anchor, source, target)` | Verify anchor references are valid |

### Commitments

| Function | Description |
|----------|-------------|
| `create_commitment(content, nonce?)` | Create a commitment hash |
| `verify_commitment(hash, content, nonce)` | Verify a commitment reveal |
| `create_commitment_block(profile, content)` | Create a commitment as a block |

### Types

`BlockType`, `ChainType`, `AnchorType`, `ContentMode` — extensible enums for all standard types.

### Storage

`MemoryStore` (default), `ChainStore` protocol for custom backends.

## Design Choices

- **Ed25519** for signatures — fast, small, deterministic, safe-by-default
- **SHA-256** for hashing — universal, well-audited, interoperable
- **JCS (RFC 8785)** for canonicalization — deterministic JSON serialization for reproducible hashes
- **Frozen dataclasses** — immutable primitives, zero framework dependency
- **Length-prefixed commitments** — prevents separator collision in commit-reveal payloads
- **Constant-time comparison** — timing-safe commitment verification via `hmac.compare_digest`

## Tiers

The SDK is structured in tiers of increasing dependency:

| Tier | What | Dependencies |
|------|------|-------------|
| **1-3** (this release) | Blocks, Chains, Anchors | `cryptography` only |
| **4** (coming) | Witness seals, liveness | + network client |
| **5** (coming) | Reputation, discovery | + synpareia network |

Tiers 1-3 work entirely offline. No server, no account, no network.

## License

Apache 2.0
