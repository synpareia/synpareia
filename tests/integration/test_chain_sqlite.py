"""Integration tests for SQLiteStore with real SQLite database."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

import synpareia
from synpareia.chain.operations import create_chain
from synpareia.chain.storage.sqlite import SQLiteStore
from synpareia.types import BlockType

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "test.db"


@pytest.fixture
def sqlite_store(db_path: Path) -> SQLiteStore:
    store = SQLiteStore(db_path)
    yield store
    store.close()


class TestSQLiteStoreBasics:
    def test_store_and_retrieve_block(
        self, profile: synpareia.Profile, sqlite_store: SQLiteStore
    ) -> None:
        block = synpareia.create_block(profile, BlockType.MESSAGE, "hello sqlite")
        sqlite_store.store_block("chain1", block)
        fetched = sqlite_store.get_block(block.id)
        assert fetched is not None
        assert fetched.id == block.id
        assert fetched.content == block.content
        assert fetched.content_hash == block.content_hash

    def test_count(self, profile: synpareia.Profile, sqlite_store: SQLiteStore) -> None:
        chain = create_chain(profile, store=sqlite_store)
        assert sqlite_store.count(chain.id) == 0
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "one"))
        assert sqlite_store.count(chain.id) == 1
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "two"))
        assert sqlite_store.count(chain.id) == 2


class TestSQLiteChainOperations:
    def test_append_and_verify(
        self, profile: synpareia.Profile, sqlite_store: SQLiteStore
    ) -> None:
        chain = create_chain(profile, store=sqlite_store)
        for i in range(5):
            block = synpareia.create_block(profile, BlockType.MESSAGE, f"msg-{i}")
            chain.append(block)
        valid, errors = chain.verify()
        assert valid, errors
        assert chain.length == 5

    def test_query_by_type(self, profile: synpareia.Profile, sqlite_store: SQLiteStore) -> None:
        chain = create_chain(profile, store=sqlite_store)
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "msg"))
        chain.append(synpareia.create_block(profile, BlockType.THOUGHT, "thought"))
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "msg2"))

        results = chain.query(block_type=str(BlockType.MESSAGE))
        assert len(results) == 2


class TestSQLitePersistence:
    def test_persists_across_instances(self, profile: synpareia.Profile, db_path: Path) -> None:
        # Write with first store
        store1 = SQLiteStore(db_path)
        chain = create_chain(profile, store=store1)
        chain_id = chain.id
        for i in range(3):
            chain.append(synpareia.create_block(profile, BlockType.MESSAGE, f"msg-{i}"))
        head_hash = chain.head_hash
        store1.close()

        # Read with second store
        store2 = SQLiteStore(db_path)
        assert store2.count(chain_id) == 3

        pos = store2.get_position(chain_id, 3)
        assert pos is not None
        assert pos.position_hash == head_hash

        block = store2.get_block_by_chain_seq(chain_id, 1)
        assert block is not None
        assert block.content == b"msg-0"
        store2.close()


class TestSQLiteExportImport:
    def test_export_import_round_trip(
        self, profile: synpareia.Profile, sqlite_store: SQLiteStore
    ) -> None:
        chain = create_chain(profile, store=sqlite_store)
        for i in range(3):
            chain.append(synpareia.create_block(profile, BlockType.MESSAGE, f"msg-{i}"))

        exported = synpareia.export_chain(chain)
        valid, errors = synpareia.verify_export(exported)
        assert valid, errors

        # Re-import into memory store
        from synpareia.chain.operations import chain_from_export

        imported = chain_from_export(exported)
        assert imported.length == 3
        v, e = imported.verify()
        assert v, e
