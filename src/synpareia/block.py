"""Block: the atomic unit of the synpareia attestation framework."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from synpareia.hash import content_hash as compute_content_hash
from synpareia.hash import jcs_canonicalize
from synpareia.signing import sign as ed25519_sign
from synpareia.signing import verify as ed25519_verify
from synpareia.types import BlockType, ContentMode


@dataclass(frozen=True)
class Block:
    """A typed, hashable, optionally signed element."""

    id: str
    type: BlockType | str
    author_id: str
    content_hash: bytes  # SHA-256 of content (always present, 32 bytes)
    created_at: datetime
    content: bytes | None = None
    signature: bytes | None = None
    metadata: dict[str, object] = field(default_factory=dict)

    @property
    def content_mode(self) -> ContentMode:
        if self.content is not None:
            return ContentMode.FULL
        return ContentMode.HASH_ONLY


def _signing_envelope(block: Block) -> dict[str, str]:
    """Build the canonical signing envelope for a block."""
    return {
        "id": block.id,
        "type": str(block.type),
        "author_id": block.author_id,
        "content_hash": block.content_hash.hex(),
        "created_at": block.created_at.isoformat(),
    }


def create_block(
    profile: object,  # Profile, but avoid circular import at runtime
    type: BlockType | str,
    content: bytes | str,
    *,
    content_mode: ContentMode = ContentMode.FULL,
    metadata: dict[str, object] | None = None,
    sign: bool = True,
) -> Block:
    """Create a new Block, optionally signed by the profile."""
    from synpareia.identity import Profile

    if not isinstance(profile, Profile):
        msg = f"Expected Profile, got {profile.__class__.__name__}"
        raise TypeError(msg)

    content_bytes = content.encode() if isinstance(content, str) else content

    block_hash = compute_content_hash(content_bytes)
    block_id = f"blk_{uuid.uuid4().hex}"
    now = datetime.now(UTC)

    stored_content = content_bytes if content_mode == ContentMode.FULL else None

    block = Block(
        id=block_id,
        type=type,
        author_id=profile.id,
        content_hash=block_hash,
        created_at=now,
        content=stored_content,
        signature=None,
        metadata=metadata or {},
    )

    if sign and profile.private_key is not None:
        envelope = _signing_envelope(block)
        canonical = jcs_canonicalize(envelope)
        sig = ed25519_sign(profile.private_key, canonical)
        # Return new frozen instance with signature
        block = Block(
            id=block.id,
            type=block.type,
            author_id=block.author_id,
            content_hash=block.content_hash,
            created_at=block.created_at,
            content=block.content,
            signature=sig,
            metadata=block.metadata,
        )

    return block


def reveal_block(block: Block, content: bytes | str) -> Block:
    """Return a new Block with content filled in. Verifies hash matches."""
    content_bytes = content.encode() if isinstance(content, str) else content

    computed = compute_content_hash(content_bytes)
    if computed != block.content_hash:
        msg = "Revealed content does not match content_hash"
        raise ValueError(msg)

    return Block(
        id=block.id,
        type=block.type,
        author_id=block.author_id,
        content_hash=block.content_hash,
        created_at=block.created_at,
        content=content_bytes,
        signature=block.signature,
        metadata=block.metadata,
    )


def verify_block(block: Block, author_public_key: bytes | None = None) -> bool:
    """Verify block integrity: content hash and signature."""
    # Verify content hash if content is present
    if block.content is not None:
        computed = compute_content_hash(block.content)
        if computed != block.content_hash:
            return False

    # Verify signature if present
    if block.signature is not None:
        if author_public_key is None:
            return False
        envelope = _signing_envelope(block)
        canonical = jcs_canonicalize(envelope)
        if not ed25519_verify(author_public_key, canonical, block.signature):
            return False

    return True
