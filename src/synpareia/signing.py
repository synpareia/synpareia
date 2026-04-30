"""Ed25519 signing and verification.

Block signing lives in :mod:`synpareia.block` (see ``_signing_envelope``);
this module only ships the raw primitive.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


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
