"""Ed25519 signing and verification."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from synpareia.hash import jcs_canonicalize

if TYPE_CHECKING:
    from synpareia.identity import Profile


def sign(private_key: bytes, data: bytes) -> bytes:
    """Sign data with an Ed25519 private key. Returns 64-byte signature."""
    key = Ed25519PrivateKey.from_private_bytes(private_key)
    return key.sign(data)


def verify(public_key: bytes, data: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature. Returns True if valid."""
    try:
        key = Ed25519PublicKey.from_public_bytes(public_key)
        key.verify(signature, data)
    except (InvalidSignature, ValueError):
        return False
    return True


def sign_block(profile: Profile, block_data: dict[str, Any]) -> bytes:
    """Sign the canonical representation of block identity fields.

    The signing envelope covers {id, type, author_id, content_hash, created_at}
    to bind authorship, type, and timestamp to the signature.
    """
    if profile.private_key is None:
        msg = "Cannot sign: profile has no private key"
        raise ValueError(msg)
    canonical = jcs_canonicalize(block_data)
    return sign(profile.private_key, canonical)
