"""Offline seal verification — no network needed."""

from __future__ import annotations

from synpareia.seal import SealPayload, seal_signing_envelope
from synpareia.signing import verify as ed25519_verify


def verify_seal(seal: SealPayload, witness_public_key: bytes) -> tuple[bool, str | None]:
    """Verify a seal's signature against the witness's public key.

    This is purely offline — once you have the seal and the witness's
    public key, you never need to contact the witness again.

    Returns (valid, error_message).
    """
    canonical = seal_signing_envelope(
        seal.seal_type,
        seal.witness_id,
        seal.sealed_at,
        target_block_hash=seal.target_block_hash,
        target_chain_id=seal.target_chain_id,
        target_chain_head=seal.target_chain_head,
    )
    if not ed25519_verify(witness_public_key, canonical, seal.witness_signature):
        return False, "Seal signature verification failed"
    return True, None


def verify_seal_block(
    seal: SealPayload,
    witness_public_key: bytes,
    *,
    expected_block_hash: bytes | None = None,
    expected_chain_id: str | None = None,
    expected_chain_head: bytes | None = None,
) -> tuple[bool, str | None]:
    """Verify a seal and optionally check that it covers the expected target.

    Use this when you have a seal and want to confirm it attests to a
    specific block hash or chain state.
    """
    valid, err = verify_seal(seal, witness_public_key)
    if not valid:
        return False, err

    if expected_block_hash is not None and seal.target_block_hash != expected_block_hash:
        return False, (
            f"Seal covers block hash {seal.target_block_hash!r}, expected {expected_block_hash!r}"
        )

    if expected_chain_id is not None and seal.target_chain_id != expected_chain_id:
        return False, (
            f"Seal covers chain {seal.target_chain_id!r}, expected {expected_chain_id!r}"
        )

    if expected_chain_head is not None and seal.target_chain_head != expected_chain_head:
        return False, (
            f"Seal covers chain head {seal.target_chain_head!r}, expected {expected_chain_head!r}"
        )

    return True, None
