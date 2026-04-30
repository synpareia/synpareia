"""Canonical content payloads for policy-ceremony blocks.

ACCEPTANCE, ACK, and CONCLUSION blocks carry a structured JSON payload.
The payload is JCS-canonicalised before being used as the block's
`content` — the existing block signing envelope (id, type, author_id,
content_hash, created_at) then covers authenticity without needing a
custom signing scheme per block type.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from synpareia.hash import jcs_canonicalize

if TYPE_CHECKING:
    from datetime import datetime


def acceptance_payload(
    *,
    chain_id: str,
    policy_hash: bytes,
    signatory_did: str,
    accepted_at: datetime,
) -> dict[str, Any]:
    return {
        "kind": "acceptance",
        "chain_id": chain_id,
        "policy_hash": policy_hash.hex(),
        "signatory_did": signatory_did,
        "accepted_at": accepted_at.isoformat(),
    }


def ack_payload(
    *,
    chain_id: str,
    policy_hash: bytes,
    witness_did: str,
    acked_at: datetime,
) -> dict[str, Any]:
    return {
        "kind": "ack",
        "chain_id": chain_id,
        "policy_hash": policy_hash.hex(),
        "witness_did": witness_did,
        "acked_at": acked_at.isoformat(),
    }


def conclusion_payload(
    *,
    chain_id: str,
    author_did: str,
    concluded_at: datetime,
    reason: str | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "kind": "conclusion",
        "chain_id": chain_id,
        "author_did": author_did,
        "concluded_at": concluded_at.isoformat(),
    }
    if reason is not None:
        out["reason"] = reason
    return out


def acceptance_bytes(**kwargs: Any) -> bytes:
    return jcs_canonicalize(acceptance_payload(**kwargs))


def ack_bytes(**kwargs: Any) -> bytes:
    return jcs_canonicalize(ack_payload(**kwargs))


def conclusion_bytes(**kwargs: Any) -> bytes:
    return jcs_canonicalize(conclusion_payload(**kwargs))
