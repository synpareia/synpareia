"""Synpareia SDK — cryptographic primitives for AI agent identity and attestation."""

from synpareia.anchor import AnchorPayload, create_anchor_block
from synpareia.anchor.verify import verify_anchor
from synpareia.block import Block, create_block, reveal_block, verify_block
from synpareia.chain import Chain, ChainPosition
from synpareia.chain.export import export_chain, verify_export
from synpareia.chain.operations import append_block, create_chain, verify_chain
from synpareia.chain.storage import ChainStore, MemoryStore
from synpareia.commitment import create_commitment, create_commitment_block, verify_commitment
from synpareia.hash import canonical_hash, content_hash, jcs_canonicalize
from synpareia.identity import Profile, from_private_key, from_public_key, generate
from synpareia.signing import sign, verify
from synpareia.types import AnchorType, BlockType, ChainType, ContentMode

__version__ = "0.1.0"

__all__ = [
    "AnchorPayload",
    "AnchorType",
    "Block",
    "BlockType",
    "Chain",
    "ChainPosition",
    "ChainStore",
    "ChainType",
    "ContentMode",
    "MemoryStore",
    "Profile",
    "__version__",
    "append_block",
    "canonical_hash",
    "content_hash",
    "create_anchor_block",
    "create_block",
    "create_chain",
    "create_commitment",
    "create_commitment_block",
    "export_chain",
    "from_private_key",
    "from_public_key",
    "generate",
    "jcs_canonicalize",
    "reveal_block",
    "sign",
    "verify",
    "verify_anchor",
    "verify_block",
    "verify_chain",
    "verify_commitment",
    "verify_export",
]
