"""Commit-reveal scheme for proof-of-thought and sealed-bid interactions."""

from __future__ import annotations

import hmac
import os
from typing import TYPE_CHECKING

from synpareia.hash import content_hash

if TYPE_CHECKING:
    from synpareia.identity import Profile

from synpareia.block import Block, create_block
from synpareia.types import BlockType, ContentMode


def _commitment_payload(content: bytes, nonce: bytes) -> bytes:
    """Build unambiguous commitment payload using length-prefixed concatenation.

    Format: 8-byte big-endian content length + content + nonce.
    This prevents separator collision (content=b"a:b",nonce=b"c" vs content=b"a",nonce=b"b:c").
    """
    return len(content).to_bytes(8, "big") + content + nonce


def create_commitment(content: bytes, nonce: bytes | None = None) -> tuple[bytes, bytes]:
    """Create a commitment hash.

    Returns (commitment_hash, nonce). Generates random 32-byte nonce if not provided.
    commitment = SHA-256(len(content) || content || nonce)
    """
    if nonce is None:
        nonce = os.urandom(32)
    return content_hash(_commitment_payload(content, nonce)), nonce


def verify_commitment(commitment_hash: bytes, content: bytes, nonce: bytes) -> bool:
    """Verify a commitment reveal. Uses constant-time comparison."""
    computed = content_hash(_commitment_payload(content, nonce))
    return hmac.compare_digest(computed, commitment_hash)


def create_commitment_block(
    profile: Profile,
    content: bytes,
    *,
    nonce: bytes | None = None,
    metadata: dict[str, object] | None = None,
    sign: bool = True,
) -> tuple[Block, bytes]:
    """Create a commitment block and return (block, nonce) for later reveal.

    The block's content is the commitment hash (hash-only mode).
    The caller keeps the nonce to reveal later.
    """
    commitment_hash, nonce_out = create_commitment(content, nonce)

    block = create_block(
        profile,
        BlockType.COMMITMENT,
        commitment_hash,
        content_mode=ContentMode.FULL,
        metadata=metadata,
        sign=sign,
    )

    return block, nonce_out
