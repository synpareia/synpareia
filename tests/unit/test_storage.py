"""Tests for MemoryStore."""

from __future__ import annotations

import synpareia
from synpareia.chain import ChainPosition
from synpareia.chain.storage import MemoryStore
from synpareia.hash import content_hash
from synpareia.types import BlockType


class TestMemoryStore:
    def test_store_and_get_block(self, profile: synpareia.Profile) -> None:
        store = MemoryStore()
        block = synpareia.create_block(profile, BlockType.MESSAGE, "hello")
        store.store_block("chain1", block)
        fetched = store.get_block(block.id)
        assert fetched is not None
        assert fetched.id == block.id

    def test_get_block_missing(self) -> None:
        store = MemoryStore()
        assert store.get_block("nonexistent") is None

    def test_store_and_get_position(self) -> None:
        store = MemoryStore()
        pos = ChainPosition(
            chain_id="chain1",
            sequence=1,
            block_id="blk_test",
            parent_hash=None,
            position_hash=b"\x00" * 32,
        )
        store.store_position("chain1", pos)
        fetched = store.get_position("chain1", 1)
        assert fetched == pos

    def test_get_position_missing(self) -> None:
        store = MemoryStore()
        assert store.get_position("chain1", 1) is None

    def test_get_positions_ordered(self, profile: synpareia.Profile) -> None:
        store = MemoryStore()
        for i in range(1, 4):
            pos = ChainPosition(
                chain_id="chain1",
                sequence=i,
                block_id=f"blk_{i}",
                parent_hash=None,
                position_hash=content_hash(str(i).encode()),
            )
            store.store_position("chain1", pos)
        positions = store.get_positions("chain1", 1, 3)
        assert [p.sequence for p in positions] == [1, 2, 3]

    def test_count(self, profile: synpareia.Profile) -> None:
        store = MemoryStore()
        assert store.count("chain1") == 0
        block = synpareia.create_block(profile, BlockType.MESSAGE, "test")
        store.store_block("chain1", block)
        pos = ChainPosition(
            chain_id="chain1",
            sequence=1,
            block_id=block.id,
            parent_hash=None,
            position_hash=b"\x00" * 32,
        )
        store.store_position("chain1", pos)
        assert store.count("chain1") == 1

    def test_get_block_by_chain_seq(self, profile: synpareia.Profile) -> None:
        store = MemoryStore()
        block = synpareia.create_block(profile, BlockType.MESSAGE, "test")
        store.store_block("chain1", block)
        pos = ChainPosition(
            chain_id="chain1",
            sequence=1,
            block_id=block.id,
            parent_hash=None,
            position_hash=b"\x00" * 32,
        )
        store.store_position("chain1", pos)
        fetched = store.get_block_by_chain_seq("chain1", 1)
        assert fetched is not None
        assert fetched.id == block.id
