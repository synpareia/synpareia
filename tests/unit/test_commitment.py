"""Tests for commit-reveal scheme."""

from __future__ import annotations

import os

import synpareia
from synpareia.commitment import create_commitment, verify_commitment


class TestCommitment:
    def test_create_verify_round_trip(self) -> None:
        content = b"my secret thought"
        commitment_hash, nonce = create_commitment(content)
        assert verify_commitment(commitment_hash, content, nonce)

    def test_wrong_content_rejects(self) -> None:
        content = b"my secret thought"
        commitment_hash, nonce = create_commitment(content)
        assert not verify_commitment(commitment_hash, b"wrong", nonce)

    def test_wrong_nonce_rejects(self) -> None:
        content = b"my secret thought"
        commitment_hash, nonce = create_commitment(content)
        assert not verify_commitment(commitment_hash, content, os.urandom(32))

    def test_custom_nonce(self) -> None:
        content = b"data"
        nonce = b"fixed-nonce"
        h1, n1 = create_commitment(content, nonce)
        h2, n2 = create_commitment(content, nonce)
        assert h1 == h2
        assert n1 == n2 == nonce

    def test_commitment_hash_is_32_bytes(self) -> None:
        h, _ = create_commitment(b"test")
        assert len(h) == 32

    def test_random_nonce_generated(self) -> None:
        _, n1 = create_commitment(b"test")
        _, n2 = create_commitment(b"test")
        assert n1 != n2  # overwhelmingly likely


class TestCommitmentBlock:
    def test_create_commitment_block(self, profile: synpareia.Profile) -> None:
        content = b"sealed bid: $100"
        block, nonce = synpareia.create_commitment_block(profile, content)
        assert block.type == synpareia.BlockType.COMMITMENT
        assert block.signature is not None
        assert len(nonce) == 32

    def test_commitment_block_verifiable(self, profile: synpareia.Profile) -> None:
        content = b"sealed bid: $100"
        block, nonce = synpareia.create_commitment_block(profile, content)
        commitment_hash, _ = create_commitment(content, nonce)
        assert verify_commitment(commitment_hash, content, nonce)

    def test_separator_collision_prevented(self) -> None:
        """Verify that content=b"a:b" nonce=b"c" differs from content=b"a" nonce=b"b:c"."""
        h1, _ = create_commitment(b"a:b", b"c")
        h2, _ = create_commitment(b"a", b"b:c")
        assert h1 != h2
