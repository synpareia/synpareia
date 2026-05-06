"""KEY_ROTATION blocks — track which Ed25519 key currently controls a DID.

Phase 0.2 of the funnel-implementation-roadmap. The synpareia DID
derivation binds a DID permanently to its **original** public key
(``did = "did:synpareia:" + sha256(original_public_key).hex()``); the
DID never changes. What does change over time is the *active
controlling key* — the key whose signature authorises new blocks
attributed to that DID.

A KEY_ROTATION block records one transition in that controlling-key
sequence:

- ``block.type == BlockType.KEY_ROTATION``
- ``block.author_id`` is the DID being rotated.
- ``block.signature`` is signed by the **old** key — the rotation is
  authorised by the current controller.
- ``block.content`` is a JSON payload with the rotation declaration
  (``did``, ``old_key_b64``, ``new_key_b64``, ``rotated_at``).

After a valid rotation, the new key signs subsequent blocks for that
DID. To resolve the current controlling key, a verifier walks the
chain forward from a known starting point and applies each
KEY_ROTATION block authored by the DID:

>>> current_key = resolve_did_key(chain, did, initial_key=original_pk)

If any rotation in the sequence is malformed or carries an old-key
signature that doesn't match the expected key at that step,
``resolve_did_key`` returns ``None`` — the chain breaks and the
current key cannot be determined from the chain alone.

The roadmap's ``simplicity-NC2`` note: no key has actually been
rotated pre-launch. KEY_ROTATION ships now to lock in the design
surface and unblock Phase 1's signature-auth model under the rotation
chain. Tests cover the protocol; first real exercise is a launch-week
dojo scenario.

Key-loss is intentionally terminal under v1: without the old private
key, no valid KEY_ROTATION block can be minted, and there is no
v1-defined recovery path. M-of-N social recovery, witness-attested
re-attestation, etc. are out of scope. See the design doc
``chain-policy-primitive.md`` for the long-term recovery strategy.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from synpareia.block import Block, _signing_envelope, verify_block
from synpareia.hash import content_hash as compute_content_hash
from synpareia.hash import jcs_canonicalize
from synpareia.signing import sign as ed25519_sign
from synpareia.types import BlockType

if TYPE_CHECKING:
    from synpareia.chain import Chain
    from synpareia.identity import Profile


__all__ = [
    "KeyRotationPayload",
    "create_key_rotation_block",
    "parse_key_rotation_payload",
    "resolve_did_key",
    "verify_key_rotation_block",
]

ED25519_PUBLIC_KEY_LENGTH = 32


@dataclass(frozen=True)
class KeyRotationPayload:
    """Structured contents of a KEY_ROTATION block.

    Mirrors the JSON shape stored in ``Block.content`` so callers can
    type-check rotations without manual JSON parsing. ``rotated_at`` is
    ISO-8601 UTC; raw bytes for keys are decoded from the base64 form
    in the payload.
    """

    did: str
    old_key: bytes
    new_key: bytes
    rotated_at: datetime


def create_key_rotation_block(
    profile: Profile,
    *,
    new_public_key: bytes,
) -> Block:
    """Mint a KEY_ROTATION block authored by ``profile``, rotating to
    ``new_public_key``.

    ``profile`` must hold the **current** private key (the one being
    rotated *out*); the block is signed with that key. The block
    declares its ``did`` and the old/new public keys in the content
    payload.

    Raises ``ValueError`` if ``profile.private_key`` is ``None`` (you
    can't rotate without the old private key) or if
    ``new_public_key`` isn't a 32-byte Ed25519 public key, or if it's
    identical to the current key (a no-op rotation reflects a caller
    bug).
    """
    if profile.private_key is None:
        msg = "create_key_rotation_block: profile must hold the current private key"
        raise ValueError(msg)
    if len(new_public_key) != ED25519_PUBLIC_KEY_LENGTH:
        msg = (
            f"create_key_rotation_block: new_public_key must be "
            f"{ED25519_PUBLIC_KEY_LENGTH} bytes, got {len(new_public_key)}"
        )
        raise ValueError(msg)
    if new_public_key == profile.public_key:
        msg = "create_key_rotation_block: new_public_key is identical to old_public_key"
        raise ValueError(msg)

    rotated_at = datetime.now(UTC)
    payload = {
        "kind": "key_rotation",
        "did": profile.id,
        "old_key_b64": base64.b64encode(profile.public_key).decode("ascii"),
        "new_key_b64": base64.b64encode(new_public_key).decode("ascii"),
        "rotated_at": rotated_at.isoformat(),
    }
    content_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    import uuid as _uuid

    block_id = f"blk_{_uuid.uuid4().hex}"
    block = Block(
        id=block_id,
        type=BlockType.KEY_ROTATION,
        author_id=profile.id,
        content_hash=compute_content_hash(content_bytes),
        created_at=rotated_at,
        content=content_bytes,
        signature=None,
        metadata={},
    )

    envelope = _signing_envelope(block)
    canonical = jcs_canonicalize(envelope)
    signature = ed25519_sign(profile.private_key, canonical)

    return Block(
        id=block.id,
        type=block.type,
        author_id=block.author_id,
        content_hash=block.content_hash,
        created_at=block.created_at,
        content=block.content,
        signature=signature,
        metadata=block.metadata,
        co_signatures=block.co_signatures,
    )


def parse_key_rotation_payload(block: Block) -> KeyRotationPayload | None:
    """Decode the structured rotation payload from a KEY_ROTATION block.

    Returns ``None`` when the block isn't a KEY_ROTATION, has no
    content, or carries malformed JSON / fields. The caller can rely
    on the returned ``KeyRotationPayload`` having well-formed
    32-byte keys and a parseable ISO-8601 timestamp.
    """
    if str(block.type) != str(BlockType.KEY_ROTATION):
        return None
    if block.content is None:
        return None
    try:
        raw = json.loads(block.content.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(raw, dict):
        return None
    if raw.get("kind") != "key_rotation":
        return None

    did = raw.get("did")
    old_b64 = raw.get("old_key_b64")
    new_b64 = raw.get("new_key_b64")
    rotated_at_str = raw.get("rotated_at")
    if not (
        isinstance(did, str)
        and isinstance(old_b64, str)
        and isinstance(new_b64, str)
        and isinstance(rotated_at_str, str)
    ):
        return None

    try:
        old_key = base64.b64decode(old_b64, validate=True)
        new_key = base64.b64decode(new_b64, validate=True)
    except (ValueError, binascii.Error):
        return None
    if len(old_key) != ED25519_PUBLIC_KEY_LENGTH or len(new_key) != ED25519_PUBLIC_KEY_LENGTH:
        return None

    try:
        rotated_at = datetime.fromisoformat(rotated_at_str)
    except ValueError:
        return None

    return KeyRotationPayload(
        did=did,
        old_key=old_key,
        new_key=new_key,
        rotated_at=rotated_at,
    )


def verify_key_rotation_block(
    block: Block,
    *,
    expected_old_key: bytes,
) -> tuple[bool, list[str]]:
    """Validate a single KEY_ROTATION block against the expected
    current controlling key.

    Returns ``(valid, errors)``. The block is valid iff:
    - ``block.type == BlockType.KEY_ROTATION``
    - The content payload parses cleanly (see ``parse_key_rotation_payload``)
    - ``payload.did == block.author_id``
    - ``payload.old_key == expected_old_key`` (rotation is authorised
      by the controlling key)
    - The block's primary signature verifies against ``expected_old_key``

    The block does **not** need a co-signature from the new key under
    v1 — the new key's first use after this block is itself proof of
    consent. Callers wanting a stronger acknowledgement requirement
    can layer one via the BlockProposal envelope.
    """
    errors: list[str] = []

    if str(block.type) != str(BlockType.KEY_ROTATION):
        errors.append(f"block.type is {str(block.type)!r}, expected 'key_rotation'")
        return False, errors

    payload = parse_key_rotation_payload(block)
    if payload is None:
        errors.append("KEY_ROTATION block has malformed content payload")
        return False, errors

    if payload.did != block.author_id:
        errors.append(
            f"payload.did {payload.did!r} does not match block.author_id {block.author_id!r}"
        )

    if payload.old_key != expected_old_key:
        errors.append("payload.old_key does not match the expected current controlling key")

    if block.signature is None:
        errors.append("KEY_ROTATION block must be signed by the old key")
        return False, errors

    if not verify_block(block, expected_old_key):
        errors.append("primary signature does not verify against expected_old_key")

    if len(payload.new_key) != ED25519_PUBLIC_KEY_LENGTH:
        errors.append(
            f"payload.new_key length is {len(payload.new_key)}, "
            f"expected {ED25519_PUBLIC_KEY_LENGTH}"
        )

    if payload.new_key == expected_old_key:
        errors.append("payload.new_key is identical to old_key (no-op rotation)")

    return not errors, errors


def resolve_did_key(
    chain: Chain,
    did: str,
    *,
    initial_key: bytes,
) -> bytes | None:
    """Walk ``chain`` forward and return the current controlling key for ``did``.

    Starts from ``initial_key`` (the controlling key at the start of
    the chain — typically the DID's original public key). For each
    KEY_ROTATION block authored by ``did``, validates the rotation
    against the running controlling key and updates it on success.

    Returns the resolved current key, or ``None`` if any rotation in
    the chain breaks (verification failed, payload mismatch, etc.).
    A chain with no KEY_ROTATION blocks for the DID returns
    ``initial_key`` unchanged.
    """
    current_key = initial_key
    for position in chain.get_positions(1):
        block = chain._store.get_block(position.block_id)  # noqa: SLF001
        if block is None:
            continue
        if str(block.type) != str(BlockType.KEY_ROTATION):
            continue
        if block.author_id != did:
            continue
        valid, _errors = verify_key_rotation_block(block, expected_old_key=current_key)
        if not valid:
            return None
        payload = parse_key_rotation_payload(block)
        if payload is None:
            # parse_key_rotation_payload would have produced an error in
            # verify_key_rotation_block; defence in depth.
            return None
        current_key = payload.new_key
    return current_key
