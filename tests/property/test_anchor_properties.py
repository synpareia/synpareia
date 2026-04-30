"""Property-based tests for anchor invariants.

Under v0.3, every chain has a POLICY genesis block at position 1 —
appended targets land at sequence 2+, so tests must use the returned
ChainPosition rather than hardcoded sequences.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

import synpareia
from synpareia.anchor import create_anchor_block
from synpareia.anchor.verify import verify_anchor
from synpareia.policy import templates
from synpareia.types import AnchorType, BlockType


class TestAnchorProperties:
    @given(
        st.text(min_size=1, max_size=100, alphabet=st.characters(categories=("L", "N"))),
    )
    @settings(max_examples=30)
    def test_anchor_round_trip_always_verifies(self, message: str) -> None:
        """Creating an anchor and immediately verifying it should always succeed."""
        profile = synpareia.generate()
        profile_b = synpareia.generate()
        source = synpareia.create_chain(profile, policy=templates.cop(profile))
        target = synpareia.create_chain(profile, policy=templates.sphere(profile, profile_b))

        block = synpareia.create_block(profile, BlockType.MESSAGE, message)
        target_pos = target.append(block)

        anchor_block, _ = create_anchor_block(
            profile,
            source,
            target_chain_id=target.id,
            target_sequence=target_pos.sequence,
            target_block_hash=block.content_hash,
        )

        valid, err = verify_anchor(anchor_block, target)
        assert valid, err

    @given(st.binary(min_size=32, max_size=32))
    @settings(max_examples=30)
    def test_wrong_hash_always_fails(self, fake_hash: bytes) -> None:
        """An anchor with a wrong target_block_hash should never verify."""
        profile = synpareia.generate()
        profile_b = synpareia.generate()
        source = synpareia.create_chain(profile, policy=templates.cop(profile))
        target = synpareia.create_chain(profile, policy=templates.sphere(profile, profile_b))

        block = synpareia.create_block(profile, BlockType.MESSAGE, "real content")
        target_pos = target.append(block)

        # Only test when fake_hash differs from real hash
        if fake_hash == block.content_hash:
            return

        anchor_block, _ = create_anchor_block(
            profile,
            source,
            target_chain_id=target.id,
            target_sequence=target_pos.sequence,
            target_block_hash=fake_hash,
        )

        valid, err = verify_anchor(anchor_block, target)
        assert not valid

    @given(
        st.lists(
            st.text(min_size=1, max_size=50, alphabet=st.characters(categories=("L", "N"))),
            min_size=2,
            max_size=10,
        ),
        st.sampled_from([AnchorType.CORRESPONDENCE, AnchorType.RECEIPT, AnchorType.BRIDGE]),
    )
    @settings(max_examples=20)
    def test_multi_anchor_verify(self, messages: list[str], anchor_type: AnchorType) -> None:
        """Multiple anchors to different positions should all verify."""
        profile = synpareia.generate()
        profile_b = synpareia.generate()
        source = synpareia.create_chain(profile, policy=templates.cop(profile))
        target = synpareia.create_chain(profile, policy=templates.sphere(profile, profile_b))

        appended: list[tuple[int, bytes]] = []
        for msg in messages:
            block = synpareia.create_block(profile, BlockType.MESSAGE, msg)
            pos = target.append(block)
            appended.append((pos.sequence, block.content_hash))

        for seq, content_hash in appended:
            anchor_block, _ = create_anchor_block(
                profile,
                source,
                target_chain_id=target.id,
                target_sequence=seq,
                target_block_hash=content_hash,
                anchor_type=anchor_type,
            )
            valid, err = verify_anchor(anchor_block, target)
            assert valid, err
