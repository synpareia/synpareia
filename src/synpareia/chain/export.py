"""Portable chain export and import."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from synpareia.block import Block
from synpareia.chain import Chain, ChainPosition
from synpareia.chain.position import compute_position_hash


def export_chain(chain: Chain, *, include_content: bool = True) -> dict[str, Any]:
    """Export a chain as a JSON-serializable dict.

    Verifiers can reconstruct and verify independently.
    """
    length = chain.length
    positions = chain.get_positions(1, length)

    exported_positions: list[dict[str, Any]] = []
    for pos in positions:
        block = chain._store.get_block(pos.block_id)
        if block is None:
            continue

        block_data: dict[str, Any] = {
            "id": block.id,
            "type": str(block.type),
            "author_id": block.author_id,
            "content_hash": block.content_hash.hex(),
            "created_at": block.created_at.isoformat(),
            "metadata": block.metadata,
        }

        if include_content and block.content is not None:
            block_data["content"] = block.content.hex()

        if block.signature is not None:
            block_data["signature"] = block.signature.hex()

        exported_positions.append(
            {
                "sequence": pos.sequence,
                "block": block_data,
                "parent_hash": pos.parent_hash.hex() if pos.parent_hash else None,
                "position_hash": pos.position_hash.hex(),
            }
        )

    return {
        "version": "1.0",
        "chain_id": chain.id,
        "owner_id": chain.owner_id,
        "chain_type": str(chain.chain_type),
        "created_at": chain.created_at.isoformat(),
        "positions": exported_positions,
        "head_hash": chain.head_hash.hex() if chain.head_hash else None,
        "metadata": chain.metadata,
    }


def verify_export(data: dict[str, Any]) -> tuple[bool, list[str]]:
    """Verify an exported chain without importing it."""
    errors: list[str] = []
    positions = data.get("positions", [])

    prev_hash: bytes | None = None

    for i, pos_data in enumerate(positions):
        expected_seq = i + 1
        seq = pos_data["sequence"]

        if seq != expected_seq:
            errors.append(f"Position {i}: expected sequence {expected_seq}, got {seq}")

        block_data = pos_data["block"]
        parent_hash_hex = pos_data.get("parent_hash")
        parent_hash = bytes.fromhex(parent_hash_hex) if parent_hash_hex else None
        position_hash = bytes.fromhex(pos_data["position_hash"])

        # Verify parent hash linkage
        if i == 0:
            if parent_hash is not None:
                errors.append("Position 1: parent_hash should be null")
        else:
            if parent_hash != prev_hash:
                errors.append(f"Position {seq}: parent_hash mismatch")

        # Recompute position hash
        created_at = datetime.fromisoformat(block_data["created_at"])
        content_hash = bytes.fromhex(block_data["content_hash"])

        expected_hash = compute_position_hash(
            sequence=seq,
            author_id=block_data["author_id"],
            block_type=block_data["type"],
            created_at=created_at,
            content_hash=content_hash,
            parent_hash=parent_hash,
        )

        if position_hash != expected_hash:
            errors.append(f"Position {seq}: position_hash mismatch")

        # Verify content hash if content is present
        if "content" in block_data:
            from synpareia.hash import content_hash as compute_hash

            content_bytes = bytes.fromhex(block_data["content"])
            computed = compute_hash(content_bytes)
            if computed != content_hash:
                errors.append(f"Position {seq}: content_hash mismatch")

        prev_hash = position_hash

    # Verify head hash
    head_hash_hex = data.get("head_hash")
    if positions and head_hash_hex:
        last_pos_hash = bytes.fromhex(positions[-1]["position_hash"])
        if bytes.fromhex(head_hash_hex) != last_pos_hash:
            errors.append("head_hash does not match last position")

    return (len(errors) == 0, errors)


def _import_chain(
    data: dict[str, Any],
    store: Any | None = None,
) -> Chain:
    """Reconstruct a chain from exported JSON."""
    from synpareia.chain.storage import MemoryStore

    if store is None:
        store = MemoryStore()

    chain_id = data["chain_id"]
    created_at = datetime.fromisoformat(data["created_at"])

    head_hash = bytes.fromhex(data["head_hash"]) if data.get("head_hash") else None

    chain = Chain(
        id=chain_id,
        owner_id=data["owner_id"],
        chain_type=data["chain_type"],
        created_at=created_at,
        head_hash=head_hash,
        metadata=data.get("metadata", {}),
        _store=store,
    )

    for pos_data in data.get("positions", []):
        block_data = pos_data["block"]

        content_bytes = None
        if "content" in block_data:
            content_bytes = bytes.fromhex(block_data["content"])

        signature = None
        if "signature" in block_data:
            signature = bytes.fromhex(block_data["signature"])

        block = Block(
            id=block_data["id"],
            type=block_data["type"],
            author_id=block_data["author_id"],
            content_hash=bytes.fromhex(block_data["content_hash"]),
            created_at=datetime.fromisoformat(block_data["created_at"]),
            content=content_bytes,
            signature=signature,
            metadata=block_data.get("metadata", {}),
        )

        parent_hash = (
            bytes.fromhex(pos_data["parent_hash"]) if pos_data.get("parent_hash") else None
        )
        position = ChainPosition(
            chain_id=chain_id,
            sequence=pos_data["sequence"],
            block_id=block.id,
            parent_hash=parent_hash,
            position_hash=bytes.fromhex(pos_data["position_hash"]),
        )

        store.store_block(chain_id, block)
        store.store_position(chain_id, position)

    return chain
