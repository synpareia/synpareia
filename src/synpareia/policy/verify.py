"""Chain policy enforcement — verify every block against the chain's policy.

Phase B of the chain-policy primitive. `verify_chain` in
``chain/operations.py`` invokes this on every chain verification
(Phase B.5 integration), so callers get policy checks by default. The
function is also exported for callers who want policy validation
without the structural walk.

Note that policy validation does **not** verify cryptographic
signatures. Use ``verify_chain(chain, public_keys=...)`` for end-to-end
crypto verification — omitting ``public_keys`` there returns
``(False, [...])`` rather than silently passing.

See docs/explorations/chain-policy-primitive.md §5.6 and §9 for the rules
enforced here.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from synpareia.block import verify_block
from synpareia.policy.lifecycle import extract_policy
from synpareia.policy.serialize import policy_hash as compute_policy_hash
from synpareia.types import BlockType

if TYPE_CHECKING:
    from synpareia.block import Block
    from synpareia.chain import Chain
    from synpareia.policy.model import PerBlockRule, Policy, Signatory, WitnessDecl


__all__ = ["verify_chain_policy"]

SUPPORTED_POLICY_VERSIONS = frozenset({"1"})


def verify_chain_policy(
    chain: Chain,
    *,
    public_keys: dict[str, bytes] | None = None,
) -> tuple[bool, list[str]]:
    """Validate every block on the chain against its policy.

    Returns ``(valid, errors)``. ``public_keys`` is an optional DID to
    Ed25519 public-key mapping; when supplied the block signatures are
    cryptographically verified, otherwise only signature presence is
    checked (where the policy requires it).

    This function does not enforce amendment-driven policy evolution;
    v1 expects a single POLICY block at position 1.
    """
    errors: list[str] = []

    genesis_position = chain.get_position(1)
    if genesis_position is None:
        return False, ["chain is empty; no POLICY block at position 1"]

    genesis_block = chain._store.get_block(genesis_position.block_id)
    if genesis_block is None:
        return False, ["POLICY block at position 1 is missing from store"]

    if str(genesis_block.type) != str(BlockType.POLICY):
        errors.append(
            f"position 1: block type is {str(genesis_block.type)!r}, "
            f"expected {str(BlockType.POLICY)!r}"
        )

    policy = extract_policy(chain)
    if policy is None:
        errors.append("chain has no well-formed POLICY block at position 1")
        return False, errors

    if policy.version not in SUPPORTED_POLICY_VERSIONS:
        errors.append(
            f"unsupported policy version {policy.version!r}; "
            f"supported: {sorted(SUPPORTED_POLICY_VERSIONS)}"
        )
        return False, errors

    expected_policy_hash = compute_policy_hash(policy)
    if chain.policy_hash is not None and chain.policy_hash != expected_policy_hash:
        errors.append("chain.policy_hash does not match policy_hash(extract_policy(chain))")
    if genesis_block.content_hash != expected_policy_hash:
        errors.append("position 1: POLICY content_hash does not match policy_hash(policy)")

    permitted_types = set(policy.block_types_permitted)
    rules_by_type = {rule.block_type: rule for rule in policy.per_block_rules}

    policy_positions = 0

    for position in chain.get_positions(1):
        block = chain._store.get_block(position.block_id)
        if block is None:
            errors.append(f"position {position.sequence}: block missing from store")
            continue

        block_type = str(block.type)
        seq = position.sequence

        if block_type == str(BlockType.POLICY):
            policy_positions += 1
            if seq != 1:
                errors.append(
                    f"position {seq}: POLICY block only allowed at position 1 "
                    "(amendments not yet supported)"
                )
            continue

        if block_type == str(BlockType.AMENDMENT):
            errors.append(
                f"position {seq}: AMENDMENT blocks are reserved for a future "
                "phase and not accepted under v1 policy verification"
            )
            continue

        if block_type not in permitted_types:
            errors.append(
                f"position {seq}: block type {block_type!r} not in policy.block_types_permitted"
            )
            continue

        rule = rules_by_type.get(block_type)
        if rule is not None:
            _check_author(block, rule, policy, seq, errors)
            if rule.signature_required and block.signature is None:
                errors.append(
                    f"position {seq}: signature required for {block_type!r} but block is unsigned"
                )

        # Lifecycle-transition blocks must always be signed, regardless of
        # whether the policy emits a PerBlockRule for them. These blocks are
        # themselves signatures on the policy.
        if (
            block_type
            in (str(BlockType.ACCEPTANCE), str(BlockType.ACK), str(BlockType.CONCLUSION))
            and block.signature is None
        ):
            errors.append(f"position {seq}: {block_type} block must be signed")

        if public_keys is not None and block.signature is not None:
            author_key = public_keys.get(block.author_id)
            if author_key is None:
                errors.append(
                    f"position {seq}: no public key provided for author {block.author_id!r}"
                )
            elif not verify_block(block, author_key, cosigner_public_keys=public_keys):
                errors.append(f"position {seq}: block signature verification failed")

        if block_type == str(BlockType.ACCEPTANCE):
            _validate_acceptance(block, chain.id, policy, expected_policy_hash, seq, errors)
        elif block_type == str(BlockType.ACK):
            _validate_ack(block, chain.id, policy, expected_policy_hash, seq, errors)
        elif block_type == str(BlockType.CONCLUSION):
            _validate_conclusion(block, chain.id, policy, seq, errors)

    if policy_positions == 0:
        errors.append("chain has no POLICY block")
    elif policy_positions > 1:
        errors.append("chain contains multiple POLICY blocks (amendments not yet supported)")

    return not errors, errors


def _check_author(
    block: Block,
    rule: PerBlockRule,
    policy: Policy,
    sequence: int,
    errors: list[str],
) -> None:
    if not rule.authors:
        return  # empty authors tuple = no author restriction
    if _author_matches(block.author_id, rule.authors, policy):
        return
    errors.append(
        f"position {sequence}: author {block.author_id!r} does not match any of "
        f"{list(rule.authors)} for block type {str(block.type)!r}"
    )


def _author_matches(
    author_did: str,
    allowed: tuple[str, ...],
    policy: Policy,
) -> bool:
    for spec in allowed:
        kind, _, selector = spec.partition(":")
        if not selector:
            continue
        if kind == "signatory" and _signatory_matches(author_did, selector, policy.signatories):
            return True
        if kind == "witness" and _witness_matches(author_did, selector, policy.witnesses):
            return True
    return False


def _signatory_matches(did: str, selector: str, signatories: tuple[Signatory, ...]) -> bool:
    if selector == did:
        return True
    return any(s.did == did and s.role == selector for s in signatories)


def _witness_matches(did: str, selector: str, witnesses: tuple[WitnessDecl, ...]) -> bool:
    if selector == did:
        return True
    return any(w.did == did and selector in w.roles for w in witnesses)


def _parse_payload(block: Block) -> dict[str, Any] | None:
    if block.content is None:
        return None
    try:
        payload = json.loads(block.content.decode())
    except (ValueError, UnicodeDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _validate_acceptance(
    block: Block,
    chain_id: str,
    policy: Policy,
    expected_policy_hash: bytes,
    sequence: int,
    errors: list[str],
) -> None:
    payload = _parse_payload(block)
    if payload is None:
        errors.append(f"position {sequence}: ACCEPTANCE payload is malformed or missing")
        return
    if payload.get("kind") != "acceptance":
        errors.append(f"position {sequence}: ACCEPTANCE payload.kind is not 'acceptance'")
    if payload.get("chain_id") != chain_id:
        errors.append(f"position {sequence}: ACCEPTANCE.chain_id does not match chain.id")
    if payload.get("policy_hash") != expected_policy_hash.hex():
        errors.append(f"position {sequence}: ACCEPTANCE.policy_hash does not match chain policy")
    if payload.get("signatory_did") != block.author_id:
        errors.append(f"position {sequence}: ACCEPTANCE.signatory_did does not match block author")
    if not policy.is_signatory(block.author_id):
        errors.append(
            f"position {sequence}: ACCEPTANCE author {block.author_id!r} "
            "is not a declared signatory"
        )


def _validate_ack(
    block: Block,
    chain_id: str,
    policy: Policy,
    expected_policy_hash: bytes,
    sequence: int,
    errors: list[str],
) -> None:
    payload = _parse_payload(block)
    if payload is None:
        errors.append(f"position {sequence}: ACK payload is malformed or missing")
        return
    if payload.get("kind") != "ack":
        errors.append(f"position {sequence}: ACK payload.kind is not 'ack'")
    if payload.get("chain_id") != chain_id:
        errors.append(f"position {sequence}: ACK.chain_id does not match chain.id")
    if payload.get("policy_hash") != expected_policy_hash.hex():
        errors.append(f"position {sequence}: ACK.policy_hash does not match chain policy")
    if payload.get("witness_did") != block.author_id:
        errors.append(f"position {sequence}: ACK.witness_did does not match block author")
    if not policy.is_witness(block.author_id):
        errors.append(
            f"position {sequence}: ACK author {block.author_id!r} is not a declared witness"
        )


def _validate_conclusion(
    block: Block,
    chain_id: str,
    policy: Policy,
    sequence: int,
    errors: list[str],
) -> None:
    payload = _parse_payload(block)
    if payload is None:
        errors.append(f"position {sequence}: CONCLUSION payload is malformed or missing")
        return
    if payload.get("kind") != "conclusion":
        errors.append(f"position {sequence}: CONCLUSION payload.kind is not 'conclusion'")
    if payload.get("chain_id") != chain_id:
        errors.append(f"position {sequence}: CONCLUSION.chain_id does not match chain.id")
    if payload.get("author_did") != block.author_id:
        errors.append(f"position {sequence}: CONCLUSION.author_did does not match block author")
    if not policy.is_signatory(block.author_id):
        errors.append(
            f"position {sequence}: CONCLUSION author {block.author_id!r} "
            "is not a declared signatory"
        )
