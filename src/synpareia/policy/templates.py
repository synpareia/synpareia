"""Canonical policy templates for each ChainType.

Templates are opinionated defaults; callers override any field via
keyword arguments. `custom(...)` is the fully-specified escape hatch.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from synpareia.policy.model import (
    AmendmentOverride,
    AmendmentRules,
    PerBlockRule,
    Policy,
    Retention,
    Signatory,
    WitnessDecl,
)
from synpareia.types import BlockType, ChainType

if TYPE_CHECKING:
    from synpareia.identity import Profile


_DEFAULT_AMENDMENTS = AmendmentRules(
    default="all_signatories_cosign",
    overrides=(
        AmendmentOverride("signatories.add", "all_signatories_cosign+new_signatory_accepts"),
        AmendmentOverride("signatories.remove", "all_signatories_cosign_except_removed"),
        AmendmentOverride("witnesses.add", "all_signatories_cosign+new_witness_acknowledges"),
        AmendmentOverride("witnesses.remove", "all_signatories_cosign"),
        AmendmentOverride(
            "retention_days.lengthen", "all_signatories_cosign+affected_witnesses_acknowledge"
        ),
        AmendmentOverride("retention_days.shorten", "all_signatories_cosign"),
        AmendmentOverride("amendment_rules", "all_signatories_cosign"),
        AmendmentOverride("termination_rule", "all_signatories_cosign"),
    ),
)


def cop(owner: Profile, **overrides: Any) -> Policy:
    """Solo author Chain-of-Presence: permissive, indefinite retention."""
    base = Policy(
        version="1",
        chain_type=str(ChainType.COP),
        signatories=(Signatory(did=owner.id, role="owner"),),
        block_types_permitted=tuple(str(t) for t in _COP_BLOCK_TYPES),
        per_block_rules=(
            PerBlockRule(
                block_type=str(BlockType.MESSAGE),
                authors=("signatory:owner",),
                signature_required=True,
                retention=Retention(mode="indefinite"),
            ),
        ),
        amendment_rules=_DEFAULT_AMENDMENTS,
        termination_rule="soft_signal",
        activation_timeout_days=1,
    )
    return _apply_overrides(base, overrides)


def sphere(
    *signatories: Profile,
    witness: Profile | None = None,
    **overrides: Any,
) -> Policy:
    """Bilateral (or multilateral) Sphere: receipt-required messaging."""
    if len(signatories) < 2:
        msg = "sphere() requires at least two signatories"
        raise ValueError(msg)

    roles = _assign_sphere_roles(len(signatories))
    sig_tuple = tuple(
        Signatory(did=profile.id, role=role)
        for profile, role in zip(signatories, roles, strict=True)
    )

    witness_decls: tuple[WitnessDecl, ...] = ()
    if witness is not None:
        witness_decls = (
            WitnessDecl(
                did=witness.id,
                roles=("timestamp",),
                retention_days=3650,
            ),
        )

    base = Policy(
        version="1",
        chain_type=str(ChainType.SPHERE),
        signatories=sig_tuple,
        block_types_permitted=tuple(str(t) for t in _SPHERE_BLOCK_TYPES),
        per_block_rules=(
            PerBlockRule(
                block_type=str(BlockType.MESSAGE),
                authors=tuple(f"signatory:{role}" for role in roles),
                signature_required=True,
                receipt_required=True,
                retention=Retention(mode="indefinite"),
            ),
            PerBlockRule(
                block_type=str(BlockType.SEAL),
                authors=(f"witness:{witness.id}",) if witness is not None else (),
                signature_required=True,
                retention=Retention(mode="bounded", duration_days=3650),
                seal_types=("timestamp", "receipt"),
            ),
        ),
        witnesses=witness_decls,
        amendment_rules=_DEFAULT_AMENDMENTS,
        termination_rule="soft_signal",
        activation_timeout_days=1,
    )
    return _apply_overrides(base, overrides)


def audit(
    *participants: Profile,
    auditors: tuple[Profile, ...] | None = None,
    **overrides: Any,
) -> Policy:
    """Audit chain: participants record, auditors retain long windows."""
    if not participants:
        msg = "audit() requires at least one participant"
        raise ValueError(msg)

    sig_tuple = tuple(Signatory(did=p.id, role="participant") for p in participants)
    witness_decls = (
        tuple(
            WitnessDecl(did=a.id, roles=("timestamp", "arbitrate"), retention_days=3650)
            for a in auditors
        )
        if auditors
        else ()
    )

    base = Policy(
        version="1",
        chain_type=str(ChainType.AUDIT),
        signatories=sig_tuple,
        block_types_permitted=tuple(str(t) for t in _AUDIT_BLOCK_TYPES),
        witnesses=witness_decls,
        amendment_rules=_DEFAULT_AMENDMENTS,
        termination_rule="conclusion_is_absolute",
        activation_timeout_days=1,
    )
    return _apply_overrides(base, overrides)


def custom(**fields: Any) -> Policy:
    """Build a fully-specified Policy from explicit fields."""
    required = {"version", "chain_type", "signatories", "block_types_permitted"}
    missing = required - fields.keys()
    if missing:
        msg = f"custom() missing required fields: {sorted(missing)}"
        raise ValueError(msg)
    fields.setdefault("amendment_rules", _DEFAULT_AMENDMENTS)
    return Policy(**fields)


_COP_BLOCK_TYPES = (
    BlockType.POLICY,
    BlockType.ACCEPTANCE,
    BlockType.ACK,
    BlockType.AMENDMENT,
    BlockType.CONCLUSION,
    BlockType.MESSAGE,
    BlockType.THOUGHT,
    BlockType.REACTION,
    BlockType.COMMITMENT,
    BlockType.ANCHOR,
    BlockType.SEAL,
    BlockType.STATE,
    BlockType.MEDIA,
    BlockType.EDIT,
    BlockType.RETRACTION,
)


_SPHERE_BLOCK_TYPES = (
    BlockType.POLICY,
    BlockType.ACCEPTANCE,
    BlockType.ACK,
    BlockType.AMENDMENT,
    BlockType.CONCLUSION,
    BlockType.MESSAGE,
    BlockType.REACTION,
    BlockType.COMMITMENT,
    BlockType.ANCHOR,
    BlockType.SEAL,
    BlockType.JOIN,
    BlockType.LEAVE,
    BlockType.EDIT,
    BlockType.RETRACTION,
    BlockType.MEDIA,
)


_AUDIT_BLOCK_TYPES = (
    BlockType.POLICY,
    BlockType.ACCEPTANCE,
    BlockType.ACK,
    BlockType.AMENDMENT,
    BlockType.CONCLUSION,
    BlockType.STATE,
    BlockType.SEAL,
    BlockType.ANCHOR,
)


def _assign_sphere_roles(n: int) -> tuple[str, ...]:
    if n == 2:
        return ("owner", "counterparty")
    return tuple(["owner"] + [f"participant_{i + 1}" for i in range(n - 1)])


def _apply_overrides(base: Policy, overrides: dict[str, Any]) -> Policy:
    if not overrides:
        return base
    from dataclasses import replace

    return replace(base, **overrides)
