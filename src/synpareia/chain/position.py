"""Position hash computation following the design doc formula."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


def compute_position_hash(
    sequence: int,
    author_id: str,
    block_type: str,
    created_at: datetime,
    content_hash: bytes,
    parent_hash: bytes | None,
) -> bytes:
    """Compute position hash per primitives-and-framework.md §3.2.

    SHA-256(sequence:author_id:type:created_at.isoformat():content_hash_hex:parent_hash_hex|'null')

    Note: this INCLUDES parent_hash, unlike the existing service code.
    """
    parent_hex = parent_hash.hex() if parent_hash is not None else "null"
    payload = (
        f"{sequence}:{author_id}:{block_type}"
        f":{created_at.isoformat()}:{content_hash.hex()}:{parent_hex}"
    )
    return hashlib.sha256(payload.encode()).digest()
