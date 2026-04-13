"""Tests for chain export and import."""

from __future__ import annotations

import copy

import synpareia
from synpareia.chain.export import verify_export
from synpareia.chain.operations import chain_from_export
from synpareia.types import BlockType


class TestExport:
    def test_export_round_trip(self, profile: synpareia.Profile) -> None:
        chain = synpareia.create_chain(profile)
        for i in range(3):
            chain.append(synpareia.create_block(profile, BlockType.MESSAGE, f"msg-{i}"))

        data = synpareia.export_chain(chain)
        assert data["version"] == "1.0"
        assert data["chain_id"] == chain.id
        assert len(data["positions"]) == 3

        # Import and verify
        imported = chain_from_export(data)
        assert imported.id == chain.id
        assert imported.length == 3
        valid, errors = imported.verify()
        assert valid, errors

    def test_export_without_content(self, profile: synpareia.Profile) -> None:
        chain = synpareia.create_chain(profile)
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "secret"))

        data = synpareia.export_chain(chain, include_content=False)
        assert "content" not in data["positions"][0]["block"]

    def test_export_with_content(self, profile: synpareia.Profile) -> None:
        chain = synpareia.create_chain(profile)
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "visible"))

        data = synpareia.export_chain(chain, include_content=True)
        assert "content" in data["positions"][0]["block"]

    def test_export_preserves_signatures(self, profile: synpareia.Profile) -> None:
        chain = synpareia.create_chain(profile)
        block = synpareia.create_block(profile, BlockType.MESSAGE, "signed")
        chain.append(block)

        data = synpareia.export_chain(chain)
        assert data["positions"][0]["block"]["signature"] is not None


class TestVerifyExport:
    def test_valid_export(self, profile: synpareia.Profile) -> None:
        chain = synpareia.create_chain(profile)
        for i in range(3):
            chain.append(synpareia.create_block(profile, BlockType.MESSAGE, f"msg-{i}"))
        data = synpareia.export_chain(chain)
        valid, errors = verify_export(data)
        assert valid, errors

    def test_tampered_position_hash(self, profile: synpareia.Profile) -> None:
        chain = synpareia.create_chain(profile)
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "test"))
        data = synpareia.export_chain(chain)

        data_copy = copy.deepcopy(data)
        data_copy["positions"][0]["position_hash"] = "00" * 32
        valid, errors = verify_export(data_copy)
        assert not valid

    def test_tampered_content(self, profile: synpareia.Profile) -> None:
        chain = synpareia.create_chain(profile)
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "original"))
        data = synpareia.export_chain(chain)

        data_copy = copy.deepcopy(data)
        data_copy["positions"][0]["block"]["content"] = b"tampered".hex()
        valid, errors = verify_export(data_copy)
        assert not valid
        assert any("content_hash" in e for e in errors)

    def test_tampered_head_hash(self, profile: synpareia.Profile) -> None:
        chain = synpareia.create_chain(profile)
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "test"))
        data = synpareia.export_chain(chain)

        data_copy = copy.deepcopy(data)
        data_copy["head_hash"] = "ff" * 32
        valid, errors = verify_export(data_copy)
        assert not valid
        assert any("head_hash" in e for e in errors)

    def test_broken_parent_hash_linkage(self, profile: synpareia.Profile) -> None:
        chain = synpareia.create_chain(profile)
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "first"))
        chain.append(synpareia.create_block(profile, BlockType.MESSAGE, "second"))
        data = synpareia.export_chain(chain)

        data_copy = copy.deepcopy(data)
        data_copy["positions"][1]["parent_hash"] = "00" * 32
        valid, errors = verify_export(data_copy)
        assert not valid
