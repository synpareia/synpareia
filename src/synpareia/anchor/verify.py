"""Cross-chain reference verification."""

from __future__ import annotations

from typing import TYPE_CHECKING

from synpareia.anchor import AnchorPayload

if TYPE_CHECKING:
    from synpareia.block import Block
    from synpareia.chain import Chain


def _extract_payload(anchor_block: Block) -> AnchorPayload | None:
    """Extract AnchorPayload from an anchor block's metadata."""
    anchor_data = anchor_block.metadata.get("anchor")
    if not isinstance(anchor_data, dict):
        return None
    return AnchorPayload.from_dict(anchor_data)


def verify_anchor(
    anchor_block: Block,
    target_chain: Chain,
) -> tuple[bool, str | None]:
    """Verify that the anchor's target_block_hash matches the actual block
    at target_sequence in target_chain.

    Returns (valid, error_message).
    """
    payload = _extract_payload(anchor_block)
    if payload is None:
        return False, "Block does not contain anchor metadata"

    if payload.target_chain_id != target_chain.id:
        return False, (
            f"Anchor targets chain {payload.target_chain_id}, but got chain {target_chain.id}"
        )

    target_block = target_chain.get_block(payload.target_sequence)
    if target_block is None:
        return False, (f"No block at sequence {payload.target_sequence} in target chain")

    if target_block.content_hash != payload.target_block_hash:
        return False, "target_block_hash does not match actual block content_hash"

    return True, None


def verify_anchor_from_block(
    anchor_block: Block,
    target_block: Block,
    target_sequence: int,
) -> tuple[bool, str | None]:
    """Verify without needing the full target chain — just the target block."""
    payload = _extract_payload(anchor_block)
    if payload is None:
        return False, "Block does not contain anchor metadata"

    if payload.target_sequence != target_sequence:
        return False, (
            f"Anchor targets sequence {payload.target_sequence}, "
            f"but got sequence {target_sequence}"
        )

    if target_block.content_hash != payload.target_block_hash:
        return False, "target_block_hash does not match actual block content_hash"

    return True, None
