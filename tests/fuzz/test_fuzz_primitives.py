"""Fuzz tests for SDK primitives.

Complements the existing property tests in `tests/property/` by pushing
harder on input ranges and adversarial shapes:

- Arbitrary bytes for block content (including empty and large).
- Random interleavings of chain operations.
- Commitment content that *looks* like a different commitment hash, to
  catch any path that might confuse commit-reveal semantics.

The property tests check invariants; these push on robustness.
"""

from __future__ import annotations

import hashlib

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

import synpareia
from synpareia import commitment as commit_module
from synpareia.policy import templates
from synpareia.types import BlockType

GENESIS = 1  # POLICY block at position 1

FUZZ = settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)


class TestBlockContentFuzz:
    """create_block accepts arbitrary bytes (including empty) without crashing."""

    @FUZZ
    @given(content=st.binary(max_size=100_000))
    def test_create_block_from_arbitrary_bytes(self, content: bytes) -> None:
        profile = synpareia.generate()
        block = synpareia.create_block(profile, BlockType.MESSAGE, content)
        assert block.content == content
        assert isinstance(block.content_hash, bytes)
        assert len(block.content_hash) == 32  # SHA-256

    @FUZZ
    @given(content=st.text(max_size=10_000))
    def test_create_block_from_text_encoded_utf8(self, content: str) -> None:
        profile = synpareia.generate()
        block = synpareia.create_block(profile, BlockType.MESSAGE, content.encode())
        # Round-trip
        assert block.content.decode() == content


class TestChainInterleavingFuzz:
    """Random interleavings of chain operations — append, verify, export,
    re-import — never produce an inconsistent state."""

    @FUZZ
    @given(counts=st.lists(st.integers(min_value=0, max_value=5), min_size=1, max_size=10))
    def test_interleaved_append_verify_export_reimport(self, counts: list[int]) -> None:
        profile = synpareia.generate()
        chain = synpareia.create_chain(profile, policy=templates.cop(profile))

        total = 0
        for batch in counts:
            for i in range(batch):
                block = synpareia.create_block(
                    profile, BlockType.MESSAGE, f"msg-{total}-{i}".encode()
                )
                chain.append(block)
            total += batch

            # Export/verify must succeed at any point
            export = synpareia.export_chain(chain)
            result = synpareia.verify_export(export, public_keys={profile.id: profile.public_key})
            # verify_export may return True, (True, []) or {"valid": True, ...}
            assert _is_valid(result)

        assert chain.length == GENESIS + total


class TestCommitmentAdversarialFuzz:
    """Commitment schemes must not confuse content that *looks* like a
    different commitment hash for an actual commitment."""

    @FUZZ
    @given(content=st.binary(max_size=1000), nonce=st.binary(min_size=16, max_size=64))
    def test_commitment_roundtrip_arbitrary(self, content: bytes, nonce: bytes) -> None:
        commitment, returned_nonce = commit_module.create_commitment(content, nonce)
        assert returned_nonce == nonce
        assert commit_module.verify_commitment(commitment, content, nonce) is True

    @FUZZ
    @given(
        real=st.binary(min_size=1, max_size=100),
        nonce=st.binary(min_size=16, max_size=64),
        fake=st.binary(min_size=1, max_size=100),
    )
    def test_commitment_rejects_different_content(
        self, real: bytes, nonce: bytes, fake: bytes
    ) -> None:
        commitment, _ = commit_module.create_commitment(real, nonce)
        if fake == real:
            return  # Hypothesis occasionally hits this; skip
        assert commit_module.verify_commitment(commitment, fake, nonce) is False

    @FUZZ
    @given(content=st.binary(min_size=1, max_size=100))
    def test_commitment_looking_content_does_not_short_circuit(self, content: bytes) -> None:
        """A content blob that happens to be 32 bytes and looks like a
        hash must still go through the normal commit-verify flow."""
        fake_hash = hashlib.sha256(content).digest()  # 32-byte blob
        nonce = b"\x00" * 16
        commitment, _ = commit_module.create_commitment(fake_hash, nonce)
        assert commit_module.verify_commitment(commitment, fake_hash, nonce) is True
        # And the commitment is different from the SHA of fake_hash alone
        assert commitment != fake_hash


class TestSigningFuzz:
    @FUZZ
    @given(message=st.binary(max_size=10_000))
    def test_sign_verify_roundtrip(self, message: bytes) -> None:
        profile = synpareia.generate()
        sig = synpareia.sign(profile.private_key, message)
        assert synpareia.verify(profile.public_key, message, sig) is True

    @FUZZ
    @given(
        message=st.binary(max_size=100),
        tamper_byte=st.integers(min_value=0, max_value=255),
    )
    def test_verify_rejects_tampered_message(self, message: bytes, tamper_byte: int) -> None:
        if not message:
            return
        profile = synpareia.generate()
        sig = synpareia.sign(profile.private_key, message)
        tampered = bytes([tamper_byte]) + message[1:]
        if tampered == message:
            return
        assert synpareia.verify(profile.public_key, tampered, sig) is False


class TestExportRoundtripFuzz:
    @FUZZ
    @given(messages=st.lists(st.binary(min_size=0, max_size=200), min_size=1, max_size=8))
    def test_export_reimport_chain_verifies(self, messages: list[bytes]) -> None:
        profile = synpareia.generate()
        chain = synpareia.create_chain(profile, policy=templates.cop(profile))
        for msg in messages:
            chain.append(synpareia.create_block(profile, BlockType.MESSAGE, msg))

        export = synpareia.export_chain(chain)
        assert _is_valid(
            synpareia.verify_export(export, public_keys={profile.id: profile.public_key})
        )


def _is_valid(result: object) -> bool:
    if result is True:
        return True
    if isinstance(result, tuple) and result and result[0] is True:
        return True
    return isinstance(result, dict) and result.get("valid") is True


# --- Spot checks --------------------------------------------------------


@pytest.mark.parametrize(
    "empty_content",
    [b"", b"\x00", b"\x00" * 100],
)
def test_block_accepts_edge_content(empty_content: bytes) -> None:
    """Empty and all-null content should still produce valid blocks."""
    profile = synpareia.generate()
    block = synpareia.create_block(profile, BlockType.MESSAGE, empty_content)
    assert block.content == empty_content
