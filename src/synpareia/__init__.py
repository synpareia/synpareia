"""Synpareia SDK — cryptographic primitives for AI agent identity and attestation."""

from synpareia.anchor import AnchorPayload, create_anchor_block
from synpareia.anchor.verify import verify_anchor
from synpareia.block import Block, create_block, reveal_block, verify_block
from synpareia.chain import Chain, ChainPosition
from synpareia.chain.export import export_chain, verify_export, verify_export_structure
from synpareia.chain.operations import (
    append_block,
    create_chain,
    verify_chain,
    verify_chain_structure,
)
from synpareia.chain.storage import ChainStore, MemoryStore
from synpareia.commitment import create_commitment, create_commitment_block, verify_commitment
from synpareia.hash import canonical_hash, content_hash, jcs_canonicalize
from synpareia.identity import Profile, from_private_key, from_public_key, generate
from synpareia.policy import (
    AmendmentOverride,
    AmendmentRules,
    GdprMetadata,
    LifecycleState,
    PerBlockRule,
    Policy,
    PolicyBuilder,
    Retention,
    RetractorRule,
    RevealerRule,
    Signatory,
    WitnessDecl,
    acceptance_bytes,
    acceptance_payload,
    ack_bytes,
    ack_payload,
    compute_lifecycle_state,
    conclusion_bytes,
    conclusion_payload,
    policy_canonical_bytes,
    policy_from_dict,
    policy_hash,
    policy_to_dict,
    templates,
    verify_chain_policy,
)
from synpareia.proposal import (
    BlockProposal,
    assemble_block,
    sign_proposal,
    start_proposal,
    verify_proposal,
)
from synpareia.seal import SealPayload, create_seal, create_seal_block
from synpareia.seal.verify import verify_seal
from synpareia.signing import sign, verify
from synpareia.threshold import (
    create_threshold_commitment,
    random_shares,
    verify_threshold_commitment,
    xor_shares,
)
from synpareia.types import AnchorType, BlockType, ChainType, ContentMode, SealType

__version__ = "0.3.0"

__all__ = [
    "AmendmentOverride",
    "AmendmentRules",
    "AnchorPayload",
    "AnchorType",
    "Block",
    "BlockProposal",
    "BlockType",
    "Chain",
    "ChainPosition",
    "ChainStore",
    "ChainType",
    "ContentMode",
    "GdprMetadata",
    "LifecycleState",
    "MemoryStore",
    "PerBlockRule",
    "Policy",
    "PolicyBuilder",
    "Profile",
    "Retention",
    "RetractorRule",
    "RevealerRule",
    "SealPayload",
    "SealType",
    "Signatory",
    "WitnessDecl",
    "__version__",
    "acceptance_bytes",
    "acceptance_payload",
    "ack_bytes",
    "ack_payload",
    "append_block",
    "assemble_block",
    "canonical_hash",
    "compute_lifecycle_state",
    "conclusion_bytes",
    "conclusion_payload",
    "content_hash",
    "create_anchor_block",
    "create_block",
    "create_chain",
    "create_commitment",
    "create_commitment_block",
    "create_seal",
    "create_seal_block",
    "create_threshold_commitment",
    "export_chain",
    "from_private_key",
    "from_public_key",
    "generate",
    "jcs_canonicalize",
    "policy_canonical_bytes",
    "policy_from_dict",
    "policy_hash",
    "policy_to_dict",
    "random_shares",
    "reveal_block",
    "sign",
    "sign_proposal",
    "start_proposal",
    "templates",
    "verify",
    "verify_anchor",
    "verify_block",
    "verify_chain",
    "verify_chain_policy",
    "verify_chain_structure",
    "verify_commitment",
    "verify_export",
    "verify_export_structure",
    "verify_proposal",
    "verify_seal",
    "verify_threshold_commitment",
    "xor_shares",
]
