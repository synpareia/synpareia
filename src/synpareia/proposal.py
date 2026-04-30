"""Multi-party block negotiation envelopes.

Per docs/explorations/chain-policy-primitive.md §5.6.2, the SDK ships a
canonical multi-signer primitive but no transport. A `BlockProposal`
bundles an unsigned block skeleton with accumulated signatures; parties
sign the same canonical envelope off-chain and pass the proposal around
through whatever channel they have. Once quorum is reached,
`assemble_block` finalises the proposal into a `Block` whose
`signature` is the proposer's and whose `co_signatures` tuple carries
the rest.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from synpareia.block import Block, _signing_envelope
from synpareia.hash import content_hash as compute_content_hash
from synpareia.hash import jcs_canonicalize
from synpareia.signing import sign as ed25519_sign
from synpareia.signing import verify as ed25519_verify
from synpareia.types import BlockType, ContentMode

if TYPE_CHECKING:
    from synpareia.identity import Profile


__all__ = [
    "BlockProposal",
    "assemble_block",
    "sign_proposal",
    "start_proposal",
    "verify_proposal",
]


@dataclass(frozen=True)
class BlockProposal:
    """A partial block collecting co-signatures from multiple parties."""

    block: Block
    """Unsigned skeleton — `signature` is None. `co_signatures` carries
    placeholder ``(did, b"")`` entries for every required cosigner so
    the signing envelope binds to the cosigner set from the outset;
    `assemble_block` swaps the placeholders for real sigs."""

    proposer_did: str
    """DID of the proposer; must equal block.author_id (checked in __post_init__)."""

    required_signers: frozenset[str]
    """DIDs expected to sign before `assemble_block` accepts the proposal."""

    signatures: dict[str, bytes] = field(default_factory=dict)
    """Accumulated signatures, keyed by signer DID."""

    def __post_init__(self) -> None:
        if self.proposer_did != self.block.author_id:
            msg = (
                f"proposer_did {self.proposer_did!r} must equal "
                f"block.author_id {self.block.author_id!r}"
            )
            raise ValueError(msg)
        if self.proposer_did not in self.required_signers:
            msg = "proposer_did must be included in required_signers"
            raise ValueError(msg)
        placeholder_dids = {did for did, _ in self.block.co_signatures}
        expected_cosigners = self.required_signers - {self.proposer_did}
        if placeholder_dids != expected_cosigners:
            msg = "block.co_signatures DIDs must equal required_signers minus the proposer"
            raise ValueError(msg)

    def envelope_bytes(self) -> bytes:
        """Canonical bytes every signer signs — matches the block's signing envelope."""
        return jcs_canonicalize(_signing_envelope(self.block))


def start_proposal(
    proposer: Profile,
    type: BlockType | str,  # noqa: A002 — API symmetry with create_block
    content: bytes | str,
    *,
    required_signers: frozenset[str] | set[str] | tuple[str, ...],
    content_mode: ContentMode = ContentMode.FULL,
    metadata: dict[str, object] | None = None,
) -> BlockProposal:
    """Draft a new proposal signed by the proposer.

    `required_signers` is the set of DIDs (including the proposer) whose
    signatures must be collected before the proposal assembles. The
    proposer's signature is added immediately.
    """
    if proposer.private_key is None:
        msg = "proposer must have a private key to start a proposal"
        raise ValueError(msg)

    required = frozenset(required_signers)
    if proposer.id not in required:
        msg = "proposer DID must be included in required_signers"
        raise ValueError(msg)

    content_bytes = content.encode() if isinstance(content, str) else content
    block_hash = compute_content_hash(content_bytes)
    block_id = f"blk_{uuid.uuid4().hex}"
    now = datetime.now(UTC)
    stored_content = content_bytes if content_mode == ContentMode.FULL else None

    # Placeholder cosigs: sigs are empty until assembly, but the DIDs
    # enter the signing envelope so every signer commits to the same
    # cosigner set. Sorted for canonical ordering.
    placeholder_cosigs = tuple((did, b"") for did in sorted(required - {proposer.id}))

    skeleton = Block(
        id=block_id,
        type=type,
        author_id=proposer.id,
        content_hash=block_hash,
        created_at=now,
        content=stored_content,
        signature=None,
        metadata=metadata or {},
        co_signatures=placeholder_cosigs,
    )

    proposal = BlockProposal(
        block=skeleton,
        proposer_did=proposer.id,
        required_signers=required,
    )
    return sign_proposal(proposal, proposer)


def sign_proposal(proposal: BlockProposal, signer: Profile) -> BlockProposal:
    """Return a new proposal with `signer`'s signature added."""
    if signer.private_key is None:
        msg = "signer must have a private key"
        raise ValueError(msg)
    if signer.id not in proposal.required_signers:
        msg = f"signer {signer.id!r} is not in required_signers"
        raise ValueError(msg)

    sig = ed25519_sign(signer.private_key, proposal.envelope_bytes())
    new_sigs = dict(proposal.signatures)
    new_sigs[signer.id] = sig
    return replace(proposal, signatures=new_sigs)


def verify_proposal(
    proposal: BlockProposal,
    public_keys: dict[str, bytes],
) -> bool:
    """Check that every collected signature verifies against the envelope."""
    envelope = proposal.envelope_bytes()
    for did, sig in proposal.signatures.items():
        key = public_keys.get(did)
        if key is None or not ed25519_verify(key, envelope, sig):
            return False
    return True


def assemble_block(
    proposal: BlockProposal,
    *,
    public_keys: dict[str, bytes],
) -> Block:
    """Finalize the proposal into a signed Block.

    ``public_keys`` must cover every DID in ``required_signers``;
    each signature is verified against the proposal envelope before
    assembly and an invalid signature raises ``ValueError``. This closes
    the path where a caller populates ``proposal.signatures`` with
    bogus bytes and assembles anyway.

    The proposer's signature becomes ``block.signature``; the rest go
    into ``block.co_signatures`` sorted by DID (matching the signing
    envelope).
    """
    missing = proposal.required_signers - proposal.signatures.keys()
    if missing:
        msg = f"proposal is missing signatures from: {sorted(missing)}"
        raise ValueError(msg)

    if proposal.proposer_did not in proposal.signatures:
        msg = "proposer must have signed before assembly"
        raise ValueError(msg)

    missing_keys = proposal.required_signers - public_keys.keys()
    if missing_keys:
        msg = f"public_keys missing DIDs: {sorted(missing_keys)}"
        raise ValueError(msg)

    envelope = proposal.envelope_bytes()
    for did, sig in proposal.signatures.items():
        if did not in public_keys:
            # Extra signer outside required_signers without a key — reject.
            msg = f"signature from {did!r} has no matching public_key"
            raise ValueError(msg)
        if not ed25519_verify(public_keys[did], envelope, sig):
            msg = f"signature from {did!r} fails verification"
            raise ValueError(msg)

    primary = proposal.signatures[proposal.proposer_did]
    cosigs = tuple(
        (did, proposal.signatures[did]) for did, _placeholder in proposal.block.co_signatures
    )

    return Block(
        id=proposal.block.id,
        type=proposal.block.type,
        author_id=proposal.block.author_id,
        content_hash=proposal.block.content_hash,
        created_at=proposal.block.created_at,
        content=proposal.block.content,
        signature=primary,
        metadata=proposal.block.metadata,
        co_signatures=cosigs,
    )
