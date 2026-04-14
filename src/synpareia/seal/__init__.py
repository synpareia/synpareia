"""Seal: third-party attestation of block or chain state."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from synpareia.block import Block
from synpareia.hash import jcs_canonicalize
from synpareia.signing import sign as ed25519_sign
from synpareia.types import BlockType, SealType


@dataclass(frozen=True)
class SealPayload:
    """A signed attestation by a witness about a block or chain state."""

    witness_id: str
    witness_signature: bytes
    seal_type: SealType | str
    sealed_at: datetime
    target_block_hash: bytes | None = None
    target_chain_id: str | None = None
    target_chain_head: bytes | None = None
    metadata: dict[str, object] = field(default_factory=dict)


def seal_signing_envelope(
    seal_type: SealType | str,
    witness_id: str,
    sealed_at: datetime,
    *,
    target_block_hash: bytes | None = None,
    target_chain_id: str | None = None,
    target_chain_head: bytes | None = None,
) -> bytes:
    """Build the JCS-canonical signing envelope for a seal.

    This is the data that gets signed by the witness's Ed25519 key.
    Both the witness service and offline verification use this function
    to ensure identical canonicalization.
    """
    envelope: dict[str, str] = {
        "seal_type": str(seal_type),
        "sealed_at": sealed_at.isoformat(),
        "witness_id": witness_id,
    }
    if target_block_hash is not None:
        envelope["target_block_hash"] = target_block_hash.hex()
    if target_chain_id is not None:
        envelope["target_chain_id"] = target_chain_id
    if target_chain_head is not None:
        envelope["target_chain_head"] = target_chain_head.hex()
    return jcs_canonicalize(envelope)


def create_seal(
    witness_private_key: bytes,
    witness_id: str,
    seal_type: SealType | str,
    *,
    target_block_hash: bytes | None = None,
    target_chain_id: str | None = None,
    target_chain_head: bytes | None = None,
    metadata: dict[str, object] | None = None,
) -> SealPayload:
    """Create a seal signed by the witness.

    Typically called by the witness service, not by SDK users directly.
    """
    sealed_at = datetime.now(UTC)
    canonical = seal_signing_envelope(
        seal_type,
        witness_id,
        sealed_at,
        target_block_hash=target_block_hash,
        target_chain_id=target_chain_id,
        target_chain_head=target_chain_head,
    )
    signature = ed25519_sign(witness_private_key, canonical)
    return SealPayload(
        witness_id=witness_id,
        witness_signature=signature,
        seal_type=seal_type,
        sealed_at=sealed_at,
        target_block_hash=target_block_hash,
        target_chain_id=target_chain_id,
        target_chain_head=target_chain_head,
        metadata=metadata or {},
    )


def create_seal_block(seal: SealPayload) -> Block:
    """Wrap a SealPayload into a Block suitable for appending to a chain.

    The block's author is the witness, and its content is the
    JCS-canonical seal envelope. The block's signature is the witness's
    seal signature.
    """
    from synpareia.hash import content_hash

    envelope = seal_signing_envelope(
        seal.seal_type,
        seal.witness_id,
        seal.sealed_at,
        target_block_hash=seal.target_block_hash,
        target_chain_id=seal.target_chain_id,
        target_chain_head=seal.target_chain_head,
    )
    return Block(
        id=f"blk_{uuid.uuid4().hex}",
        type=BlockType.SEAL,
        author_id=seal.witness_id,
        content_hash=content_hash(envelope),
        created_at=seal.sealed_at,
        content=envelope,
        signature=seal.witness_signature,
        metadata={
            "seal_type": str(seal.seal_type),
            **(
                {"target_block_hash": seal.target_block_hash.hex()}
                if seal.target_block_hash
                else {}
            ),
            **({"target_chain_id": seal.target_chain_id} if seal.target_chain_id else {}),
            **(
                {"target_chain_head": seal.target_chain_head.hex()}
                if seal.target_chain_head
                else {}
            ),
        },
    )
