"""Anchor traversal: finding and resolving cross-chain references."""

from __future__ import annotations

from typing import TYPE_CHECKING

from synpareia.anchor import AnchorPayload
from synpareia.types import BlockType

if TYPE_CHECKING:
    from synpareia.block import Block
    from synpareia.chain import Chain, ChainPosition


def find_anchors(
    chain: Chain,
    *,
    anchor_type: str | None = None,
) -> list[tuple[ChainPosition, AnchorPayload]]:
    """Find all anchor blocks in a chain, optionally filtered by type."""
    results: list[tuple[ChainPosition, AnchorPayload]] = []

    anchor_positions = chain.query(block_type=str(BlockType.ANCHOR), limit=10000)

    for pos, block in anchor_positions:
        anchor_data = block.metadata.get("anchor")
        if not isinstance(anchor_data, dict):
            continue
        payload = AnchorPayload.from_dict(anchor_data)
        if anchor_type is not None and str(payload.anchor_type) != anchor_type:
            continue
        results.append((pos, payload))

    return results


def resolve_anchor(
    anchor_payload: AnchorPayload,
    chains: dict[str, Chain],
) -> Block | None:
    """Given a map of available chains, resolve the anchor to the target block."""
    target_chain = chains.get(anchor_payload.target_chain_id)
    if target_chain is None:
        return None

    block = target_chain.get_block(anchor_payload.target_sequence)
    if block is None:
        return None

    if block.content_hash != anchor_payload.target_block_hash:
        return None

    return block


def trace_correspondence(
    source_chain: Chain,
    target_chain: Chain,
) -> list[tuple[ChainPosition, ChainPosition]]:
    """Find all correspondence anchors between two chains.

    Returns paired positions (source_position, target_position).
    """
    from synpareia.types import AnchorType

    anchors = find_anchors(source_chain, anchor_type=str(AnchorType.CORRESPONDENCE))

    pairs: list[tuple[ChainPosition, ChainPosition]] = []
    for source_pos, payload in anchors:
        if payload.target_chain_id != target_chain.id:
            continue
        target_pos = target_chain.get_position(payload.target_sequence)
        if target_pos is None:
            continue
        target_block = target_chain.get_block(payload.target_sequence)
        if target_block is None:
            continue
        if target_block.content_hash != payload.target_block_hash:
            continue
        pairs.append((source_pos, target_pos))

    return pairs
