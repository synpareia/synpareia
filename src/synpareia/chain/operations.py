"""Chain factory and operations: create, append, verify."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from synpareia.chain import Chain, ChainPosition
from synpareia.chain.position import compute_position_hash

if TYPE_CHECKING:
    from synpareia.block import Block
    from synpareia.chain.storage import ChainStore
    from synpareia.identity import Profile
    from synpareia.policy.model import Policy


def create_chain(
    owner: Profile,
    *,
    policy: Policy,
    store: ChainStore | None = None,
    metadata: dict[str, object] | None = None,
) -> Chain:
    """Create a new chain with an explicit policy at genesis.

    A POLICY block is appended at position 1 signed by the owner. The
    chain's lifecycle state is `PROPOSED` if the policy names additional
    signatories, otherwise `ACTIVE`.
    """
    if store is None:
        from synpareia.chain.storage import MemoryStore

        store = MemoryStore()

    from synpareia.policy.serialize import policy_hash as _policy_hash

    chain = Chain(
        id=f"chn_{uuid.uuid4().hex}",
        owner_id=owner.id,
        chain_type=policy.chain_type,
        created_at=datetime.now(UTC),
        head_hash=None,
        metadata=metadata or {},
        policy_hash=_policy_hash(policy),
        _store=store,
    )

    _append_genesis_policy_block(chain, owner, policy)
    return chain


def _append_genesis_policy_block(chain: Chain, owner: Profile, policy: Policy) -> None:
    from synpareia.block import create_block
    from synpareia.policy.serialize import policy_canonical_bytes
    from synpareia.types import BlockType, ContentMode

    content = policy_canonical_bytes(policy)
    block = create_block(
        owner,
        BlockType.POLICY,
        content,
        content_mode=ContentMode.FULL,
        sign=True,
    )
    append_block(chain, block)


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


def verify_chain(
    chain: Chain,
    *,
    public_keys: dict[str, bytes] | None = None,
) -> tuple[bool, list[str]]:
    """Walk all positions, recompute hashes, check linkage, enforce policy, and verify signatures.

    Returns ``(is_valid, errors)``. Surfaces structural errors (hash
    linkage, position hashes, head_hash), policy errors (block type
    permitted, author match, signature presence, ACCEPTANCE/ACK/
    CONCLUSION shape, AMENDMENT rejection), and — when ``public_keys``
    is supplied — cryptographic signature failures.

    ``public_keys`` is a DID→public_key mapping. If omitted, any block
    carrying a signature is flagged as unverified and the chain fails
    verification (fail-closed — the SDK refuses to claim a chain is
    valid without having checked its signatures). Callers who only want
    a structural pre-check can use :func:`verify_chain_structure`.
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

    # Verify the genesis block is a POLICY block with matching hash
    if chain.policy_hash is not None and positions:
        from synpareia.types import BlockType

        genesis = chain._store.get_block(positions[0].block_id)
        if genesis is None:
            errors.append("Genesis block missing")
        else:
            if str(genesis.type) != str(BlockType.POLICY):
                errors.append("Genesis block is not a POLICY block")
            elif genesis.content_hash != chain.policy_hash:
                errors.append("Genesis POLICY content_hash does not match chain.policy_hash")

    # Policy-level validation — only run when the chain has a parseable policy.
    # A chain without a policy block fails above; we skip policy rules in that case
    # since there is nothing to enforce against.
    if positions and not errors:
        from synpareia.policy.verify import verify_chain_policy

        _, policy_errors = verify_chain_policy(chain, public_keys=public_keys)
        errors.extend(policy_errors)

        if public_keys is None:
            signed_count = sum(
                1
                for pos in positions
                if (b := chain._store.get_block(pos.block_id)) is not None
                and b.signature is not None
            )
            if signed_count:
                errors.append(
                    f"no public_keys supplied; {signed_count} block "
                    "signature(s) unverified (pass public_keys to verify, "
                    "or use verify_chain_structure for a structure-only check)"
                )

    return (len(errors) == 0, errors)


def verify_chain_structure(chain: Chain) -> tuple[bool, list[str]]:
    """Structural verification only — positions, hashes, head, and policy block presence.

    Does **not** run policy-body rules and does **not** verify any
    signatures. Intended for scenarios where a caller needs to confirm
    a chain is internally consistent before attempting crypto (e.g.
    during import before public keys are available). Production
    callers should use :func:`verify_chain` with ``public_keys``.
    """
    errors: list[str] = []
    length = chain._store.count(chain.id)
    positions = chain._store.get_positions(chain.id, 1, length)

    prev_hash: bytes | None = None
    for i, pos in enumerate(positions):
        expected_seq = i + 1
        if pos.sequence != expected_seq:
            errors.append(f"Position {i}: expected sequence {expected_seq}, got {pos.sequence}")
        if i == 0:
            if pos.parent_hash is not None:
                errors.append("Position 1: parent_hash should be None")
        elif pos.parent_hash != prev_hash:
            errors.append(f"Position {pos.sequence}: parent_hash mismatch")

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

    if length > 0 and positions and chain.head_hash != positions[-1].position_hash:
        errors.append("Chain head_hash does not match last position")

    return (len(errors) == 0, errors)


def chain_from_export(
    data: dict[str, object],
    store: ChainStore | None = None,
) -> Chain:
    """Reconstruct a chain from exported JSON.

    Performs structural verification. Signature verification is the caller's
    responsibility — after import, call ``verify_chain(chain, public_keys=...)``
    to cryptographically validate the block signatures.
    """
    from synpareia.chain.export import _import_chain, verify_export_structure

    errors = verify_export_structure(data)
    if errors:
        msg = f"Export verification failed: {'; '.join(errors)}"
        raise ValueError(msg)

    return _import_chain(data, store)
