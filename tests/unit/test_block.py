"""Tests for Block creation, verification, and content modes."""

from __future__ import annotations

import synpareia
from synpareia.hash import content_hash
from synpareia.types import BlockType, ContentMode


class TestCreateBlock:
    def test_full_content(self, profile: synpareia.Profile) -> None:
        block = synpareia.create_block(profile, BlockType.MESSAGE, "Hello!")
        assert block.content == b"Hello!"
        assert block.content_hash == content_hash(b"Hello!")
        assert block.content_mode == ContentMode.FULL
        assert block.signature is not None
        assert block.author_id == profile.id
        assert block.id.startswith("blk_")

    def test_hash_only(self, profile: synpareia.Profile) -> None:
        block = synpareia.create_block(
            profile,
            BlockType.THOUGHT,
            "secret thought",
            content_mode=ContentMode.HASH_ONLY,
        )
        assert block.content is None
        assert block.content_hash == content_hash(b"secret thought")
        assert block.content_mode == ContentMode.HASH_ONLY

    def test_unsigned(self, profile: synpareia.Profile) -> None:
        block = synpareia.create_block(
            profile,
            BlockType.MESSAGE,
            "unsigned",
            sign=False,
        )
        assert block.signature is None

    def test_with_metadata(self, profile: synpareia.Profile) -> None:
        meta = {"key": "value", "count": 42}
        block = synpareia.create_block(
            profile,
            BlockType.MESSAGE,
            "data",
            metadata=meta,
        )
        assert block.metadata == meta

    def test_custom_type(self, profile: synpareia.Profile) -> None:
        block = synpareia.create_block(profile, "custom_event", "payload")
        assert block.type == "custom_event"

    def test_bytes_content(self, profile: synpareia.Profile) -> None:
        data = b"\x00\x01\x02\xff"
        block = synpareia.create_block(profile, BlockType.MEDIA, data)
        assert block.content == data


class TestRevealBlock:
    def test_reveal_matching_content(self, profile: synpareia.Profile) -> None:
        block = synpareia.create_block(
            profile,
            BlockType.THOUGHT,
            "hidden",
            content_mode=ContentMode.HASH_ONLY,
        )
        revealed = synpareia.reveal_block(block, "hidden")
        assert revealed.content == b"hidden"
        assert revealed.content_hash == block.content_hash
        assert revealed.signature == block.signature

    def test_reveal_wrong_content_raises(self, profile: synpareia.Profile) -> None:
        block = synpareia.create_block(
            profile,
            BlockType.THOUGHT,
            "hidden",
            content_mode=ContentMode.HASH_ONLY,
        )
        import pytest

        with pytest.raises(ValueError, match="does not match"):
            synpareia.reveal_block(block, "wrong content")


class TestVerifyBlock:
    def test_valid_signed_block(self, profile: synpareia.Profile) -> None:
        block = synpareia.create_block(profile, BlockType.MESSAGE, "test")
        assert synpareia.verify_block(block, profile.public_key)

    def test_tampered_content(self, profile: synpareia.Profile) -> None:
        block = synpareia.create_block(profile, BlockType.MESSAGE, "test")
        # Create tampered block with wrong content but same hash
        from synpareia.block import Block

        tampered = Block(
            id=block.id,
            type=block.type,
            author_id=block.author_id,
            content_hash=block.content_hash,
            created_at=block.created_at,
            content=b"tampered",
            signature=block.signature,
            metadata=block.metadata,
        )
        assert not synpareia.verify_block(tampered, profile.public_key)

    def test_wrong_public_key(self, profile: synpareia.Profile) -> None:
        block = synpareia.create_block(profile, BlockType.MESSAGE, "test")
        other = synpareia.generate()
        assert not synpareia.verify_block(block, other.public_key)

    def test_unsigned_block_verifies_content(self, profile: synpareia.Profile) -> None:
        block = synpareia.create_block(
            profile,
            BlockType.MESSAGE,
            "test",
            sign=False,
        )
        assert synpareia.verify_block(block)

    def test_hash_only_without_content_verifies(self, profile: synpareia.Profile) -> None:
        block = synpareia.create_block(
            profile,
            BlockType.THOUGHT,
            "hidden",
            content_mode=ContentMode.HASH_ONLY,
        )
        # No content to verify hash against, sig still valid
        assert synpareia.verify_block(block, profile.public_key)

    def test_signature_without_public_key_fails(self, profile: synpareia.Profile) -> None:
        block = synpareia.create_block(profile, BlockType.MESSAGE, "test")
        assert not synpareia.verify_block(block)  # no public key provided
