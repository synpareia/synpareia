"""Property-based tests for chain invariants."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

import synpareia
from synpareia.types import BlockType

# Generate a list of messages to append
message_contents = st.lists(
    st.text(min_size=1, max_size=100, alphabet=st.characters(categories=("L", "N", "P", "Z"))),
    min_size=1,
    max_size=20,
)


class TestChainInvariants:
    @given(message_contents)
    @settings(max_examples=30)
    def test_chain_length_equals_appends(self, messages: list[str]) -> None:
        profile = synpareia.generate()
        chain = synpareia.create_chain(profile)
        for msg in messages:
            block = synpareia.create_block(profile, BlockType.MESSAGE, msg)
            chain.append(block)
        assert chain.length == len(messages)

    @given(message_contents)
    @settings(max_examples=30)
    def test_sequence_is_monotonic(self, messages: list[str]) -> None:
        profile = synpareia.generate()
        chain = synpareia.create_chain(profile)
        positions = []
        for msg in messages:
            block = synpareia.create_block(profile, BlockType.MESSAGE, msg)
            pos = chain.append(block)
            positions.append(pos)
        for i, pos in enumerate(positions):
            assert pos.sequence == i + 1

    @given(message_contents)
    @settings(max_examples=30)
    def test_verify_always_passes_untampered(self, messages: list[str]) -> None:
        profile = synpareia.generate()
        chain = synpareia.create_chain(profile)
        for msg in messages:
            block = synpareia.create_block(profile, BlockType.MESSAGE, msg)
            chain.append(block)
        valid, errors = chain.verify()
        assert valid, errors

    @given(
        st.lists(
            st.text(min_size=1, max_size=50, alphabet=st.characters(categories=("L", "N"))),
            min_size=2,
            max_size=10,
        )
    )
    @settings(max_examples=20)
    def test_tampering_detected(self, messages: list[str]) -> None:
        """Tampering with any position hash should be detected."""
        profile = synpareia.generate()
        chain = synpareia.create_chain(profile)
        for msg in messages:
            block = synpareia.create_block(profile, BlockType.MESSAGE, msg)
            chain.append(block)

        # Tamper with a random position
        import random

        tamper_seq = random.randint(1, len(messages))
        pos = chain._store.get_position(chain.id, tamper_seq)

        from synpareia.chain import ChainPosition

        tampered = ChainPosition(
            chain_id=pos.chain_id,
            sequence=pos.sequence,
            block_id=pos.block_id,
            parent_hash=pos.parent_hash,
            position_hash=b"\xff" * 32,
        )
        chain._store._positions[(chain.id, tamper_seq)] = tampered

        # If we tampered with the last position, update head_hash too
        if tamper_seq == len(messages):
            chain.head_hash = tampered.position_hash

        valid, errors = chain.verify()
        assert not valid

    @given(message_contents)
    @settings(max_examples=30)
    def test_parent_hash_linkage(self, messages: list[str]) -> None:
        """Each position's parent_hash should equal the previous position's position_hash."""
        profile = synpareia.generate()
        chain = synpareia.create_chain(profile)
        positions = []
        for msg in messages:
            block = synpareia.create_block(profile, BlockType.MESSAGE, msg)
            pos = chain.append(block)
            positions.append(pos)

        assert positions[0].parent_hash is None
        for i in range(1, len(positions)):
            assert positions[i].parent_hash == positions[i - 1].position_hash
