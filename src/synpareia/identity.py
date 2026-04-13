"""Agent identity: keypair generation and DID derivation."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from synpareia.types import DID_PREFIX


@dataclass(frozen=True)
class Profile:
    """An agent's cryptographic identity.

    Wraps an Ed25519 keypair with a deterministic DID.
    """

    id: str  # did:synpareia:<SHA-256(public_key_bytes) hex>
    public_key: bytes  # raw 32-byte Ed25519 public key
    private_key: bytes | None  # raw 32-byte private key (None for public-only)


def _derive_did(public_key: bytes) -> str:
    """Derive a DID from a public key: did:synpareia:<SHA-256(pk) hex>."""
    return DID_PREFIX + hashlib.sha256(public_key).hexdigest()


def generate() -> Profile:
    """Generate a new Ed25519 keypair and derive a Profile."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    return Profile(
        id=_derive_did(public_bytes),
        public_key=public_bytes,
        private_key=private_bytes,
    )


def from_private_key(private_key: bytes) -> Profile:
    """Reconstruct a Profile from a raw 32-byte Ed25519 private key."""
    key = Ed25519PrivateKey.from_private_bytes(private_key)
    public_bytes = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    return Profile(
        id=_derive_did(public_bytes),
        public_key=public_bytes,
        private_key=private_key,
    )


def from_public_key(public_key: bytes) -> Profile:
    """Create a public-only Profile (can verify but not sign)."""
    return Profile(
        id=_derive_did(public_key),
        public_key=public_key,
        private_key=None,
    )


def load(public_key_b64: str, private_key_b64: str | None = None) -> Profile:
    """Load a Profile from base64-encoded keys."""
    public_bytes = base64.b64decode(public_key_b64)
    private_bytes = base64.b64decode(private_key_b64) if private_key_b64 else None

    if private_bytes is not None:
        return from_private_key(private_bytes)

    return from_public_key(public_bytes)
