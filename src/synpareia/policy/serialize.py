"""Policy serialization: dataclass <-> §9 JSON shape; JCS canonical bytes; hash.

`policy_hash(p)` is the exact value stored as the POLICY block's
`content_hash` — it binds the chain to its policy at genesis.
"""

from __future__ import annotations

from typing import Any

from synpareia.hash import content_hash, jcs_canonicalize
from synpareia.policy.model import (
    AmendmentOverride,
    AmendmentRules,
    GdprMetadata,
    PerBlockRule,
    Policy,
    Retention,
    RetractorRule,
    RevealerRule,
    Signatory,
    WitnessDecl,
)


def policy_to_dict(policy: Policy) -> dict[str, Any]:
    """Render a Policy in its canonical §9 JSON shape."""
    out: dict[str, Any] = {
        "version": policy.version,
        "chain_type": policy.chain_type,
        "signatories": [_signatory_to_dict(s) for s in policy.signatories],
        "block_types_permitted": list(policy.block_types_permitted),
        "per_block_rules": {
            rule.block_type: _rule_to_dict(rule) for rule in policy.per_block_rules
        },
        "witnesses": [_witness_to_dict(w) for w in policy.witnesses],
        "allowed_revealers": {
            "by_block_type": {r.block_type: list(r.allowed) for r in policy.allowed_revealers}
        },
        "allowed_retractors": {
            "by_block_type": {r.block_type: list(r.allowed) for r in policy.allowed_retractors}
        },
        "fork_permitted": policy.fork_permitted,
        "non_equivocation_enabled": policy.non_equivocation_enabled,
        "amendment_rules": _amendment_rules_to_dict(policy.amendment_rules),
        "termination_rule": policy.termination_rule,
        "activation_timeout_days": policy.activation_timeout_days,
    }
    if policy.gdpr is not None:
        out["gdpr"] = _gdpr_to_dict(policy.gdpr)
    return out


def policy_from_dict(data: dict[str, Any]) -> Policy:
    """Parse a §9 JSON dict into a Policy dataclass."""
    return Policy(
        version=data["version"],
        chain_type=data["chain_type"],
        signatories=tuple(_signatory_from_dict(s) for s in data.get("signatories", [])),
        block_types_permitted=tuple(data.get("block_types_permitted", [])),
        per_block_rules=tuple(
            _rule_from_dict(bt, r) for bt, r in data.get("per_block_rules", {}).items()
        ),
        witnesses=tuple(_witness_from_dict(w) for w in data.get("witnesses", [])),
        allowed_revealers=tuple(
            RevealerRule(block_type=bt, allowed=tuple(allowed))
            for bt, allowed in data.get("allowed_revealers", {}).get("by_block_type", {}).items()
        ),
        allowed_retractors=tuple(
            RetractorRule(block_type=bt, allowed=tuple(allowed))
            for bt, allowed in data.get("allowed_retractors", {}).get("by_block_type", {}).items()
        ),
        fork_permitted=bool(data.get("fork_permitted", False)),
        non_equivocation_enabled=bool(data.get("non_equivocation_enabled", False)),
        amendment_rules=_amendment_rules_from_dict(data.get("amendment_rules", {})),
        termination_rule=data.get("termination_rule", "soft_signal"),
        activation_timeout_days=int(data.get("activation_timeout_days", 1)),
        gdpr=_gdpr_from_dict(data["gdpr"]) if "gdpr" in data else None,
    )


def policy_canonical_bytes(policy: Policy) -> bytes:
    """JCS-canonical bytes of the policy dict. Stored as POLICY block content."""
    return jcs_canonicalize(policy_to_dict(policy))


def policy_hash(policy: Policy) -> bytes:
    """SHA-256 of the policy's canonical bytes. Matches POLICY block content_hash."""
    return content_hash(policy_canonical_bytes(policy))


def _signatory_to_dict(s: Signatory) -> dict[str, Any]:
    return {"did": s.did, "role": s.role}


def _signatory_from_dict(d: dict[str, Any]) -> Signatory:
    return Signatory(did=d["did"], role=d["role"])


def _witness_to_dict(w: WitnessDecl) -> dict[str, Any]:
    out: dict[str, Any] = {"did": w.did, "roles": list(w.roles)}
    if w.retention_days is not None:
        out["retention_days"] = w.retention_days
    return out


def _witness_from_dict(d: dict[str, Any]) -> WitnessDecl:
    return WitnessDecl(
        did=d["did"],
        roles=tuple(d.get("roles", [])),
        retention_days=d.get("retention_days"),
    )


def _retention_to_dict(r: Retention) -> dict[str, Any]:
    return {"mode": r.mode, "duration_days": r.duration_days}


def _retention_from_dict(d: dict[str, Any]) -> Retention:
    return Retention(mode=d["mode"], duration_days=d.get("duration_days"))


def _rule_to_dict(rule: PerBlockRule) -> dict[str, Any]:
    out: dict[str, Any] = {
        "authors": list(rule.authors),
        "signature_required": rule.signature_required,
        "receipt_required": rule.receipt_required,
    }
    if rule.retention is not None:
        out["retention"] = _retention_to_dict(rule.retention)
    if rule.seal_types:
        out["seal_types"] = list(rule.seal_types)
    return out


def _rule_from_dict(block_type: str, d: dict[str, Any]) -> PerBlockRule:
    return PerBlockRule(
        block_type=block_type,
        authors=tuple(d.get("authors", [])),
        signature_required=bool(d.get("signature_required", True)),
        receipt_required=bool(d.get("receipt_required", False)),
        retention=_retention_from_dict(d["retention"]) if "retention" in d else None,
        seal_types=tuple(d.get("seal_types", [])),
    )


def _amendment_rules_to_dict(rules: AmendmentRules) -> dict[str, Any]:
    # `default` and `overrides` are kept in separate keys so an override whose
    # path is literally "default" doesn't collide with the rule's own default
    # field (close-read finding 2026-04-30).
    out: dict[str, Any] = {"default": rules.default}
    if rules.overrides:
        out["overrides"] = {ov.path: ov.requirement for ov in rules.overrides}
    return out


def _amendment_rules_from_dict(data: dict[str, Any]) -> AmendmentRules:
    default = data.get("default", "all_signatories_cosign")
    # New shape: overrides nested under `overrides`. Old shape (pre-0.3.1):
    # overrides as flat siblings of `default`. Read both for backward compat.
    nested = data.get("overrides")
    if isinstance(nested, dict):
        overrides = tuple(AmendmentOverride(path=k, requirement=v) for k, v in nested.items())
    else:
        overrides = tuple(
            AmendmentOverride(path=k, requirement=v) for k, v in data.items() if k != "default"
        )
    return AmendmentRules(default=default, overrides=overrides)


def _gdpr_to_dict(g: GdprMetadata) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if g.controller_did is not None:
        out["controller_did"] = g.controller_did
    if g.purpose is not None:
        out["purpose"] = g.purpose
    if g.lawful_basis is not None:
        out["lawful_basis"] = g.lawful_basis
    if g.retention_days is not None:
        out["retention_days"] = g.retention_days
    if g.subject_rights_contact is not None:
        out["subject_rights_contact"] = g.subject_rights_contact
    return out


def _gdpr_from_dict(d: dict[str, Any]) -> GdprMetadata:
    return GdprMetadata(
        controller_did=d.get("controller_did"),
        purpose=d.get("purpose"),
        lawful_basis=d.get("lawful_basis"),
        retention_days=d.get("retention_days"),
        subject_rights_contact=d.get("subject_rights_contact"),
    )
