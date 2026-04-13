"""End-to-end integration test: full conversation workflow with all primitives."""

from __future__ import annotations

import synpareia
from synpareia.anchor import create_anchor_block
from synpareia.anchor.traversal import find_anchors, trace_correspondence
from synpareia.chain.export import verify_export
from synpareia.chain.operations import chain_from_export
from synpareia.commitment import create_commitment, verify_commitment
from synpareia.types import AnchorType, BlockType, ChainType, ContentMode


class TestFullWorkflow:
    def test_two_agent_conversation(self) -> None:
        """Two agents meet, exchange messages through a sphere, anchor their CoPs,
        do a commit-reveal, export and verify everything."""

        # === Setup: Two agents, their CoPs, and a shared sphere ===
        alice = synpareia.generate()
        bob = synpareia.generate()

        alice_cop = synpareia.create_chain(alice, ChainType.COP)
        bob_cop = synpareia.create_chain(bob, ChainType.COP)
        sphere = synpareia.create_chain(alice, ChainType.SPHERE, metadata={"name": "test-conv"})

        # === Join events ===
        alice_join = synpareia.create_block(alice, BlockType.JOIN, "alice joins")
        bob_join = synpareia.create_block(bob, BlockType.JOIN, "bob joins")
        sphere.append(alice_join)
        sphere.append(bob_join)
        alice_cop.append(alice_join)
        bob_cop.append(bob_join)

        # === Alice sends a message ===
        msg1 = synpareia.create_block(alice, BlockType.MESSAGE, "Hello Bob!")
        sphere_pos1 = sphere.append(msg1)
        alice_cop.append(msg1)

        # Alice anchors her CoP entry to the sphere
        create_anchor_block(
            alice,
            alice_cop,
            target_chain_id=sphere.id,
            target_sequence=sphere_pos1.sequence,
            target_block_hash=msg1.content_hash,
            anchor_type=AnchorType.CORRESPONDENCE,
        )

        # === Bob receives and responds ===
        # Bob records receipt in his CoP
        create_anchor_block(
            bob,
            bob_cop,
            target_chain_id=sphere.id,
            target_sequence=sphere_pos1.sequence,
            target_block_hash=msg1.content_hash,
            anchor_type=AnchorType.RECEIPT,
        )

        msg2 = synpareia.create_block(bob, BlockType.MESSAGE, "Hi Alice! Nice to meet you.")
        sphere_pos2 = sphere.append(msg2)
        bob_cop.append(msg2)

        create_anchor_block(
            bob,
            bob_cop,
            target_chain_id=sphere.id,
            target_sequence=sphere_pos2.sequence,
            target_block_hash=msg2.content_hash,
            anchor_type=AnchorType.CORRESPONDENCE,
        )

        # === Commit-reveal: Alice commits to a thought before sharing ===
        thought_content = b"I think Bob is a fascinating conversationalist"
        commitment_hash, nonce = create_commitment(thought_content)
        commitment_block = synpareia.create_block(
            alice,
            BlockType.COMMITMENT,
            commitment_hash,
        )
        alice_cop.append(commitment_block)

        # Later, Alice reveals her thought
        assert verify_commitment(commitment_hash, thought_content, nonce)
        thought_block = synpareia.create_block(
            alice,
            BlockType.THOUGHT,
            thought_content,
            content_mode=ContentMode.HASH_ONLY,
        )
        alice_cop.append(thought_block)

        # === Alice sends a private thought (hash-only in sphere) ===
        private_thought = synpareia.create_block(
            alice,
            BlockType.THOUGHT,
            "Deep analysis of the conversation so far...",
            content_mode=ContentMode.HASH_ONLY,
        )
        alice_cop.append(private_thought)

        # === Verification ===
        # All chains should verify
        for name, chain in [("alice_cop", alice_cop), ("bob_cop", bob_cop), ("sphere", sphere)]:
            valid, errors = chain.verify()
            assert valid, f"{name} failed: {errors}"

        # Verify all blocks
        assert synpareia.verify_block(msg1, alice.public_key)
        assert synpareia.verify_block(msg2, bob.public_key)

        # Alice's anchors to sphere should verify
        alice_anchors = find_anchors(alice_cop)
        assert len(alice_anchors) == 1  # 1 correspondence anchor
        for _, payload in alice_anchors:
            if payload.target_chain_id == sphere.id:
                block = sphere.get_block(payload.target_sequence)
                assert block is not None

        # Bob's anchors should verify
        bob_anchors = find_anchors(bob_cop)
        assert len(bob_anchors) == 2  # 1 receipt + 1 correspondence

        # Trace correspondence
        bob_corr = trace_correspondence(bob_cop, sphere)
        assert len(bob_corr) == 1

        # === Export and verify ===
        for chain in [alice_cop, bob_cop, sphere]:
            exported = synpareia.export_chain(chain)
            valid, errors = verify_export(exported)
            assert valid, f"Export verification failed: {errors}"

            # Round-trip import
            imported = chain_from_export(exported)
            assert imported.length == chain.length
            v, e = imported.verify()
            assert v, e

    def test_multi_message_chain_integrity(self) -> None:
        """Verify chain integrity holds across many messages."""
        agent = synpareia.generate()
        chain = synpareia.create_chain(agent)

        for i in range(50):
            block = synpareia.create_block(agent, BlockType.MESSAGE, f"message #{i}")
            chain.append(block)

        assert chain.length == 50
        valid, errors = chain.verify()
        assert valid, errors

        # Export and verify
        exported = synpareia.export_chain(chain)
        valid, errors = verify_export(exported)
        assert valid, errors
