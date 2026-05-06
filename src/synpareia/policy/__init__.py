"""Chain policy primitive — see docs/explorations/chain-policy-primitive.md."""

from __future__ import annotations

from synpareia.policy import templates
from synpareia.policy.builder import PolicyBuilder
from synpareia.policy.envelope import (
    acceptance_bytes,
    acceptance_payload,
    ack_bytes,
    ack_payload,
    conclusion_bytes,
    conclusion_payload,
)
from synpareia.policy.key_rotation import (
    KeyRotationPayload,
    create_key_rotation_block,
    parse_key_rotation_payload,
    resolve_did_key,
    verify_key_rotation_block,
)
from synpareia.policy.lifecycle import (
    accepted_signatories,
    compute_lifecycle_state,
    extract_policy,
)
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
from synpareia.policy.serialize import (
    policy_canonical_bytes,
    policy_from_dict,
    policy_hash,
    policy_to_dict,
)
from synpareia.policy.verify import verify_chain_policy
from synpareia.types import LifecycleState

__all__ = [
    "AmendmentOverride",
    "AmendmentRules",
    "GdprMetadata",
    "KeyRotationPayload",
    "LifecycleState",
    "PerBlockRule",
    "Policy",
    "PolicyBuilder",
    "Retention",
    "RetractorRule",
    "RevealerRule",
    "Signatory",
    "WitnessDecl",
    "accepted_signatories",
    "acceptance_bytes",
    "acceptance_payload",
    "ack_bytes",
    "ack_payload",
    "compute_lifecycle_state",
    "conclusion_bytes",
    "conclusion_payload",
    "create_key_rotation_block",
    "extract_policy",
    "parse_key_rotation_payload",
    "policy_canonical_bytes",
    "policy_from_dict",
    "policy_hash",
    "policy_to_dict",
    "resolve_did_key",
    "templates",
    "verify_chain_policy",
    "verify_key_rotation_block",
]
