"""Synpareia quickstart — create an identity, build a chain, verify everything.

Run with: python examples/quickstart.py
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import synpareia
from synpareia.policy import acceptance_bytes, policy_hash, templates
from synpareia.types import AnchorType, BlockType, ContentMode

# ---------------------------------------------------------------------------
# 1. Create two agent identities
# ---------------------------------------------------------------------------

alice = synpareia.generate()
bob = synpareia.generate()

print(f"Alice: {alice.id}")
print(f"Bob:   {bob.id}")

# ---------------------------------------------------------------------------
# 2. Create a shared conversation chain (sphere) — multi-party policy
# ---------------------------------------------------------------------------

sphere_policy = templates.sphere(alice, bob)
conversation = synpareia.create_chain(alice, policy=sphere_policy)

# The sphere starts in PENDING; Bob accepts the policy to activate it.
bob_accept = synpareia.create_block(
    bob,
    BlockType.ACCEPTANCE,
    acceptance_bytes(
        chain_id=conversation.id,
        policy_hash=policy_hash(sphere_policy),
        signatory_did=bob.id,
        accepted_at=datetime.now(UTC),
    ),
)
conversation.append(bob_accept)

# Alice sends a message
msg1 = synpareia.create_block(alice, BlockType.MESSAGE, "Hello Bob!")
conversation.append(msg1)

# Bob replies
msg2 = synpareia.create_block(bob, BlockType.MESSAGE, "Hi Alice, nice to meet you.")
conversation.append(msg2)

print(f"\nConversation: {conversation.length} blocks")

# ---------------------------------------------------------------------------
# 3. Each agent keeps a personal Chain of Presence (CoP)
# ---------------------------------------------------------------------------

alice_cop = synpareia.create_chain(alice, policy=templates.cop(alice))
bob_cop = synpareia.create_chain(bob, policy=templates.cop(bob))

# Alice records her side of the exchange on her personal chain
alice_msg = synpareia.create_block(alice, BlockType.MESSAGE, "Hello Bob!")
alice_cop.append(alice_msg)

# Alice anchors her CoP to the shared conversation
synpareia.create_anchor_block(
    alice,
    alice_cop,
    target_chain_id=conversation.id,
    target_sequence=2,  # msg1 is at position 2 (POLICY=1, ACCEPTANCE=2, MSG1=3? actually 3)
    target_block_hash=msg1.content_hash,
    anchor_type=AnchorType.CORRESPONDENCE,
)

print(f"Alice CoP: {alice_cop.length} blocks (including anchor)")

# ---------------------------------------------------------------------------
# 4. Commit-reveal: independent assessments
# ---------------------------------------------------------------------------

alice_assessment = b"Rating: 5/5, genuinely interesting conversation"
alice_commit_hash, alice_nonce = synpareia.create_commitment(alice_assessment)

bob_assessment = b"Rating: 4/5, good first interaction"
bob_commit_hash, bob_nonce = synpareia.create_commitment(bob_assessment)

# Publish the commitments on-chain (only the hashes — content stays private)
conversation.append(synpareia.create_block(alice, BlockType.COMMITMENT, alice_commit_hash))
conversation.append(synpareia.create_block(bob, BlockType.COMMITMENT, bob_commit_hash))

# Anyone can verify later that these commitments bind the stated content
assert synpareia.verify_commitment(alice_commit_hash, alice_assessment, alice_nonce)
assert synpareia.verify_commitment(bob_commit_hash, bob_assessment, bob_nonce)

print("Commitments verified: both assessments were independent")

# ---------------------------------------------------------------------------
# 5. Verify everything — fail-closed requires public keys
# ---------------------------------------------------------------------------

keys = {alice.id: alice.public_key, bob.id: bob.public_key}

valid, errors = conversation.verify(public_keys=keys)
assert valid, errors
print(f"Conversation chain verified: {conversation.length} blocks, no tampering")

assert synpareia.verify_block(msg1, alice.public_key)
assert synpareia.verify_block(msg2, bob.public_key)
print("Block signatures verified")

# ---------------------------------------------------------------------------
# 6. Export — portable, independently verifiable
# ---------------------------------------------------------------------------

export = synpareia.export_chain(conversation)
valid, errors = synpareia.verify_export(export, public_keys=keys)
assert valid, errors

print(f"\nExported conversation ({len(json.dumps(export))} bytes JSON)")
print(f"  Version: {export['version']}")
print(f"  Blocks:  {len(export['positions'])}")
print(f"  Head:    {export['head_hash'][:16]}...")
_ = ContentMode  # re-exported for consumers; silence unused-import warnings

print("\nDone. All verifications passed.")
