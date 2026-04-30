"""Chain lifecycle state classifier.

The chain's state is a function of its block sequence; this module
encodes that function. See chain-policy-primitive.md §3.5.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from synpareia.policy.serialize import policy_from_dict
from synpareia.types import BlockType, LifecycleState

if TYPE_CHECKING:
    from synpareia.chain import Chain
    from synpareia.policy.model import Policy


__all__ = ["LifecycleState", "compute_lifecycle_state", "extract_policy", "accepted_signatories"]


def extract_policy(chain: Chain) -> Policy | None:
    """Parse the POLICY block at position 1, or return None if missing/invalid."""
    import json

    position = chain.get_position(1)
    if position is None:
        return None

    block = chain._store.get_block(position.block_id)
    if block is None or str(block.type) != str(BlockType.POLICY) or block.content is None:
        return None

    try:
        data = json.loads(block.content.decode())
    except (ValueError, UnicodeDecodeError):
        return None

    if not isinstance(data, dict):
        return None

    try:
        return policy_from_dict(data)
    except (KeyError, TypeError, ValueError):
        return None


def accepted_signatories(chain: Chain, policy: Policy) -> frozenset[str]:
    """DIDs of signatories whose ACCEPTANCE block is present and well-formed."""
    import json

    accepted: set[str] = set()
    policy_hash_hex = _policy_hash(policy).hex()

    for position in chain.get_positions(1):
        block = chain._store.get_block(position.block_id)
        if block is None or str(block.type) != str(BlockType.ACCEPTANCE) or block.content is None:
            continue
        try:
            payload = json.loads(block.content.decode())
        except (ValueError, UnicodeDecodeError):
            continue
        if not isinstance(payload, dict):
            continue
        if payload.get("policy_hash") != policy_hash_hex:
            continue
        if payload.get("chain_id") != chain.id:
            continue
        signatory_did = payload.get("signatory_did")
        if signatory_did == block.author_id and policy.is_signatory(block.author_id):
            accepted.add(block.author_id)

    # The proposer (author of the POLICY block) implicitly accepts at genesis.
    proposer = _proposer_did(chain)
    if proposer is not None and policy.is_signatory(proposer):
        accepted.add(proposer)

    return frozenset(accepted)


def compute_lifecycle_state(chain: Chain) -> LifecycleState:
    """Classify a chain's current lifecycle state from its block sequence."""
    policy = extract_policy(chain)
    if policy is None:
        # No well-formed policy at genesis; chain is malformed by v1 rules but
        # return PROPOSED conservatively — verify_chain_policy will flag it.
        return LifecycleState.PROPOSED

    if _has_conclusion(chain):
        return LifecycleState.CONCLUDED

    required = set(policy.signatory_dids)
    if not required:
        # Policy declares no signatories; chain is trivially active.
        return LifecycleState.ACTIVE

    accepted = accepted_signatories(chain, policy)
    if accepted == required:
        return LifecycleState.ACTIVE
    if accepted:
        return LifecycleState.PENDING
    return LifecycleState.PROPOSED


def _proposer_did(chain: Chain) -> str | None:
    position = chain.get_position(1)
    if position is None:
        return None
    block = chain._store.get_block(position.block_id)
    return block.author_id if block is not None else None


def _has_conclusion(chain: Chain) -> bool:
    for position in chain.get_positions(1):
        block = chain._store.get_block(position.block_id)
        if block is not None and str(block.type) == str(BlockType.CONCLUSION):
            return True
    return False


def _policy_hash(policy: Policy) -> bytes:
    from synpareia.policy.serialize import policy_hash

    return policy_hash(policy)
