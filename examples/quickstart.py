"""Synpareia quickstart — create an identity, build a chain, verify everything.

Run with: python examples/quickstart.py
"""

import json

import synpareia

# ---------------------------------------------------------------------------
# 1. Create two agent identities
# ---------------------------------------------------------------------------

alice = synpareia.generate()
bob = synpareia.generate()

print(f"Alice: {alice.id}")
print(f"Bob:   {bob.id}")

# ---------------------------------------------------------------------------
# 2. Create a shared conversation chain (sphere)
# ---------------------------------------------------------------------------

conversation = synpareia.create_chain(alice, chain_type="sphere")

# Alice sends a message
msg1 = synpareia.create_block(alice, type="message", content="Hello Bob!")
pos1 = synpareia.append_block(conversation, msg1)

# Bob replies
msg2 = synpareia.create_block(bob, type="message", content="Hi Alice, nice to meet you.")
pos2 = synpareia.append_block(conversation, msg2)

# Alice shares a thought (hash-only — content is private)
thought = synpareia.create_block(
    alice,
    type="thought",
    content="Bob seems thoughtful",
    content_mode=synpareia.ContentMode.HASH_ONLY,
)
pos3 = synpareia.append_block(conversation, thought)

print(f"\nConversation: {conversation.length} blocks")

# ---------------------------------------------------------------------------
# 3. Each agent keeps a personal Chain of Presence (CoP)
# ---------------------------------------------------------------------------

alice_cop = synpareia.create_chain(alice, chain_type="cop")
bob_cop = synpareia.create_chain(bob, chain_type="cop")

# Alice records her message in her personal chain
alice_msg = synpareia.create_block(alice, type="message", content="Hello Bob!")
synpareia.append_block(alice_cop, alice_msg)

# Alice anchors her CoP to the shared conversation
anchor_block, anchor_pos = synpareia.create_anchor_block(
    alice,
    alice_cop,
    target_chain_id=conversation.id,
    target_sequence=1,
    target_block_hash=msg1.content_hash,
    anchor_type="correspondence",
)

print(f"Alice CoP: {alice_cop.length} blocks (including anchor)")

# ---------------------------------------------------------------------------
# 4. Commit-reveal: independent assessments
# ---------------------------------------------------------------------------

# Both agents commit to assessments before seeing each other's
alice_commitment, alice_nonce = synpareia.create_commitment_block(
    alice,
    content=b"Rating: 5/5, genuinely interesting conversation",
)

bob_commitment, bob_nonce = synpareia.create_commitment_block(
    bob,
    content=b"Rating: 4/5, good first interaction",
)

# Add commitments to the conversation
synpareia.append_block(conversation, alice_commitment)
synpareia.append_block(conversation, bob_commitment)

# Now reveal — anyone can verify these were committed before being seen
assert synpareia.verify_commitment(
    alice_commitment.content,
    b"Rating: 5/5, genuinely interesting conversation",
    alice_nonce,
)
assert synpareia.verify_commitment(
    bob_commitment.content,
    b"Rating: 4/5, good first interaction",
    bob_nonce,
)

print("Commitments verified: both assessments were independent")

# ---------------------------------------------------------------------------
# 5. Verify everything
# ---------------------------------------------------------------------------

# Verify the conversation chain is intact
valid, errors = synpareia.verify_chain(conversation)
assert valid, errors
print(f"Conversation chain verified: {conversation.length} blocks, no tampering")

# Verify individual block signatures
assert synpareia.verify_block(msg1, alice.public_key)
assert synpareia.verify_block(msg2, bob.public_key)
print("Block signatures verified")

# ---------------------------------------------------------------------------
# 6. Export — portable, independently verifiable
# ---------------------------------------------------------------------------

export = synpareia.export_chain(conversation)
valid, errors = synpareia.verify_export(export)
assert valid, errors

# The export is plain JSON — send it to anyone
print(f"\nExported conversation ({len(json.dumps(export))} bytes JSON)")
print(f"  Version: {export['version']}")
print(f"  Blocks:  {len(export['positions'])}")
print(f"  Head:    {export['head_hash'][:16]}...")

print("\nDone. All verifications passed.")
