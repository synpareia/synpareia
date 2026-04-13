"""Chain factory and operations: create, append, verify."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from synpareia.chain import Chain, ChainPosition
from synpareia.chain.position import compute_position_hash
from synpareia.types import ChainType

if TYPE_CHECKING:
    from synpareia.block import Block
    from synpareia.chain.storage import ChainStore
    from synpareia.identity import Profile


def create_chain(
    owner: Profile,
    chain_type: ChainType | str = ChainType.COP,
    *,
    store: ChainStore | None = None,
    metadata: dict[str, object] | None = None,
) -> Chain:
    """Create a new chain owned by the given profile."""
    if store is None:
        from synpareia.chain.storage import MemoryStore

        store = MemoryStore()

    return Chain(
        id=f"chn_{uuid.uuid4().hex}",
        owner_id=owner.id,
        chain_type=chain_type,
        created_at=datetime.now(UTC),
        head_hash=None,
        metadata=metadata or {},
        _store=store,
    )


def append_block(chain: Chain, block: Block) -> ChainPosition:
    """Append a block to a chain, returning its ChainPosition."""
    current_length = chain._store.count(chain.id)
    sequence = current_length + 1
    parent_hash = chain.head_hash

    position_hash = compute_position_hash(
        sequence=sequence,
        author_id=block.author_id,
        block_type=str(block.type),
        created_at=block.created_at,
        content_hash=block.content_hash,
        parent_hash=parent_hash,
    )

    position = ChainPosition(
        chain_id=chain.id,
        sequence=sequence,
        block_id=block.id,
        parent_hash=parent_hash,
        position_hash=position_hash,
    )

    chain._store.store_block(chain.id, block)
    chain._store.store_position(chain.id, position)
    chain.head_hash = position_hash

    return position


def verify_chain(chain: Chain) -> tuple[bool, list[str]]:
    """Walk all positions, recompute hashes, check linkage.

    Returns (is_valid, errors). Empty errors means chain is intact.
    """
    errors: list[str] = []
    length = chain._store.count(chain.id)
    positions = chain._store.get_positions(chain.id, 1, length)

    prev_hash: bytes | None = None

    for i, pos in enumerate(positions):
        expected_seq = i + 1

        if pos.sequence != expected_seq:
            errors.append(f"Position {i}: expected sequence {expected_seq}, got {pos.sequence}")

        # Verify parent hash linkage
        if i == 0:
            if pos.parent_hash is not None:
                errors.append("Position 1: parent_hash should be None")
        else:
            if pos.parent_hash != prev_hash:
                errors.append(f"Position {pos.sequence}: parent_hash mismatch")

        # Recompute position hash
        block = chain._store.get_block(pos.block_id)
        if block is None:
            errors.append(f"Position {pos.sequence}: block {pos.block_id} not found")
            prev_hash = pos.position_hash
            continue

        expected_hash = compute_position_hash(
            sequence=pos.sequence,
            author_id=block.author_id,
            block_type=str(block.type),
            created_at=block.created_at,
            content_hash=block.content_hash,
            parent_hash=pos.parent_hash,
        )

        if pos.position_hash != expected_hash:
            errors.append(f"Position {pos.sequence}: position_hash mismatch")

        prev_hash = pos.position_hash

    # Verify head_hash matches last position
    if length > 0 and positions and chain.head_hash != positions[-1].position_hash:
        errors.append("Chain head_hash does not match last position")

    return (len(errors) == 0, errors)


def chain_from_export(
    data: dict[str, object],
    store: ChainStore | None = None,
) -> Chain:
    """Reconstruct a chain from exported JSON with verification."""
    from synpareia.chain.export import _import_chain, verify_export

    valid, errors = verify_export(data)
    if not valid:
        msg = f"Export verification failed: {'; '.join(errors)}"
        raise ValueError(msg)

    return _import_chain(data, store)
