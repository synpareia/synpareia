"""End-to-end integration test: full conversation workflow with all primitives."""

from __future__ import annotations

from datetime import UTC, datetime

import synpareia
from synpareia.anchor import create_anchor_block
from synpareia.anchor.traversal import find_anchors, trace_correspondence
from synpareia.chain.export import verify_export
from synpareia.chain.operations import chain_from_export
from synpareia.commitment import create_commitment, verify_commitment
from synpareia.policy import acceptance_bytes, policy_hash, templates
from synpareia.types import AnchorType, BlockType, ContentMode, LifecycleState


class TestFullWorkflow:
    def test_two_agent_conversation(self) -> None:
        """Two agents meet, exchange messages through a sphere, anchor their CoPs,
        do a commit-reveal, export and verify everything."""

        alice = synpareia.generate()
        bob = synpareia.generate()

        alice_cop = synpareia.create_chain(alice, policy=templates.cop(alice))
        bob_cop = synpareia.create_chain(bob, policy=templates.cop(bob))
        sphere_policy = templates.sphere(alice, bob)
        sphere = synpareia.create_chain(
            alice, policy=sphere_policy, metadata={"name": "test-conv"}
        )
        assert sphere.state == LifecycleState.PENDING

        # Bob accepts the sphere policy — chain becomes ACTIVE
        bob_accept = synpareia.create_block(
            bob,
            BlockType.ACCEPTANCE,
            acceptance_bytes(
                chain_id=sphere.id,
                policy_hash=policy_hash(sphere_policy),
                signatory_did=bob.id,
                accepted_at=datetime.now(UTC),
            ),
        )
        sphere.append(bob_accept)
        assert sphere.state == LifecycleState.ACTIVE

        # === Join events ===
        # JOIN blocks live on the sphere (permitted by SPHERE policy). Each
        # agent records their presence on their own solo CoP via STATE.
        sphere.append(synpareia.create_block(alice, BlockType.JOIN, "alice joins"))
        sphere.append(synpareia.create_block(bob, BlockType.JOIN, "bob joins"))
        alice_cop.append(synpareia.create_block(alice, BlockType.STATE, "joined sphere"))
        bob_cop.append(synpareia.create_block(bob, BlockType.STATE, "joined sphere"))

        # === Alice sends a message ===
        msg1 = synpareia.create_block(alice, BlockType.MESSAGE, "Hello Bob!")
        sphere_pos1 = sphere.append(msg1)
        alice_cop.append(msg1)

        create_anchor_block(
            alice,
            alice_cop,
            target_chain_id=sphere.id,
            target_sequence=sphere_pos1.sequence,
            target_block_hash=msg1.content_hash,
            anchor_type=AnchorType.CORRESPONDENCE,
        )

        # === Bob receives and responds ===
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

        assert verify_commitment(commitment_hash, thought_content, nonce)
        thought_block = synpareia.create_block(
            alice,
            BlockType.THOUGHT,
            thought_content,
            content_mode=ContentMode.HASH_ONLY,
        )
        alice_cop.append(thought_block)

        private_thought = synpareia.create_block(
            alice,
            BlockType.THOUGHT,
            "Deep analysis of the conversation so far...",
            content_mode=ContentMode.HASH_ONLY,
        )
        alice_cop.append(private_thought)

        keys = {alice.id: alice.public_key, bob.id: bob.public_key}
        for name, chain in [("alice_cop", alice_cop), ("bob_cop", bob_cop), ("sphere", sphere)]:
            valid, errors = chain.verify(public_keys=keys)
            assert valid, f"{name} failed: {errors}"

        assert synpareia.verify_block(msg1, alice.public_key)
        assert synpareia.verify_block(msg2, bob.public_key)

        alice_anchors = find_anchors(alice_cop)
        assert len(alice_anchors) == 1
        for _, payload in alice_anchors:
            if payload.target_chain_id == sphere.id:
                block = sphere.get_block(payload.target_sequence)
                assert block is not None

        bob_anchors = find_anchors(bob_cop)
        assert len(bob_anchors) == 2

        bob_corr = trace_correspondence(bob_cop, sphere)
        assert len(bob_corr) == 1

        for chain in [alice_cop, bob_cop, sphere]:
            exported = synpareia.export_chain(chain)
            valid, errors = verify_export(exported, public_keys=keys)
            assert valid, f"Export verification failed: {errors}"

            imported = chain_from_export(exported)
            assert imported.length == chain.length
            v, e = imported.verify(public_keys=keys)
            assert v, e

    def test_multi_message_chain_integrity(self) -> None:
        """Verify chain integrity holds across many messages."""
        agent = synpareia.generate()
        chain = synpareia.create_chain(agent, policy=templates.cop(agent))

        for i in range(50):
            block = synpareia.create_block(agent, BlockType.MESSAGE, f"message #{i}")
            chain.append(block)

        assert chain.length == 1 + 50  # POLICY + 50 messages
        valid, errors = chain.verify(public_keys={agent.id: agent.public_key})
        assert valid, errors

        exported = synpareia.export_chain(chain)
        valid, errors = verify_export(exported, public_keys={agent.id: agent.public_key})
        assert valid, errors
