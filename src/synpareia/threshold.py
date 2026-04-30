"""Threshold commitment: n-of-n XOR-share commitments.

Per docs/explorations/chain-policy-primitive.md §5 (S5 regime 2), a
threshold commitment is
    H(len(content) || content || n₁ ⊕ n₂ ⊕ ... ⊕ nₖ)
where each nᵢ is held by a distinct participant. The n-of-n security
property — that no proper subset of the shares can open the commitment
— holds only when **no single party ever holds all n shares in the
same process**.

The functions below are pure constructors: they do not enforce
distributed custody on their behalf. Calling ``create_threshold_commitment``
with every share materialised in one process briefly reconstructs the
joint nonce inside that process and returns it to the caller. In that
flow the primitive is effectively 1-of-n: the caller who assembled it
can open the commitment unilaterally against :mod:`synpareia.commitment`.

The intended usage is either:

- **Escrow:** a trusted assembler composes the commitment, persists or
  escrows the joint nonce, and promises to discard the shares. Downstream
  verifiers treat the escrow as the reveal path. ``create_threshold_commitment``
  returns the joint nonce precisely for this flow.
- **Distributed custody:** each party generates their own share with
  :func:`random_shares` locally, publishes a sub-commitment to their
  share, and only reveals the share after a trigger. The joint nonce
  is never materialised in a single process until reveal. The callers
  of this module must orchestrate that protocol themselves; this
  module ships only the combinator and the verifier.

This module ships the XOR-all (n-of-n) variant. Shamir k-of-n is
future work — it needs GF(2^b) arithmetic that deserves its own
design pass — and is not part of v1.

Shape mirrors :mod:`synpareia.commitment`:
- :func:`create_threshold_commitment` builds a commitment from content
  plus nonce shares and returns the reconstructed joint nonce.
- :func:`verify_threshold_commitment` rebuilds the joint nonce from a
  share set and checks it against the commitment hash.
- :func:`xor_shares` and :func:`random_shares` are standalone building
  blocks callers may use directly.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from synpareia.commitment import create_commitment, verify_commitment

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

__all__ = [
    "create_threshold_commitment",
    "random_shares",
    "verify_threshold_commitment",
    "xor_shares",
]


def xor_shares(shares: Iterable[bytes]) -> bytes:
    """XOR-combine byte strings.

    All shares must be the same length. Returns a byte string of that
    length. Raises ``ValueError`` on an empty input or length mismatch.
    """
    shares_list = list(shares)
    if not shares_list:
        msg = "xor_shares requires at least one share"
        raise ValueError(msg)
    length = len(shares_list[0])
    for i, s in enumerate(shares_list):
        if len(s) != length:
            msg = (
                f"shares must be equal length; share 0 is {length} bytes, "
                f"share {i} is {len(s)} bytes"
            )
            raise ValueError(msg)
    result = 0
    for s in shares_list:
        result ^= int.from_bytes(s, "big")
    return result.to_bytes(length, "big")


_MIN_SHARE_LENGTH = 16
"""Minimum share length in bytes. 16 bytes = 128 bits of entropy per share,
enough that an attacker cannot exhaustively search the joint-nonce space
(which is the actual secret); shorter shares degrade silently into a
weaker commitment under XOR-all."""


def random_shares(n: int, length: int = 32) -> list[bytes]:
    """Return *n* cryptographically random byte strings of the given length.

    ``n`` must be at least 2 — a 1-of-1 threshold commitment is a
    single-party commitment, for which :func:`create_commitment` is
    the right primitive. ``length`` must be at least 16 bytes; shorter
    shares don't carry enough entropy for the XOR-all construction to
    resist unilateral preimage search over small content spaces.
    """
    if n < 2:
        msg = "threshold commitments require at least 2 shares (n >= 2)"
        raise ValueError(msg)
    if length < _MIN_SHARE_LENGTH:
        msg = f"share length must be at least {_MIN_SHARE_LENGTH} bytes"
        raise ValueError(msg)
    return [os.urandom(length) for _ in range(n)]


def create_threshold_commitment(
    content: bytes,
    shares: Sequence[bytes],
) -> tuple[bytes, bytes]:
    """Build a threshold commitment over ``content`` with ``shares``.

    Returns ``(commitment_hash, joint_nonce)``. The joint nonce is the
    XOR of every share; it is returned for callers that need to persist
    or escrow it. **The caller who invokes this function holds all
    shares in memory for the duration of the call and receives the
    joint nonce** — in that single-process flow the primitive is
    effectively 1-of-n. For a true n-of-n reveal, each party must
    generate their share locally and publish a commitment to it before
    the joint nonce is ever materialised; see the module docstring for
    the orchestration requirements.

    The n-of-n reveal path normally calls
    :func:`verify_threshold_commitment` against the share set, not
    :func:`synpareia.commitment.verify_commitment` against the joint
    nonce; either works, but the share-set path is the one that
    documents the threshold structure to downstream verifiers.
    """
    if len(shares) < 2:
        msg = "threshold commitments require at least 2 shares"
        raise ValueError(msg)
    joint = xor_shares(shares)
    if joint == b"\x00" * len(joint):
        msg = (
            "shares XOR to an all-zero joint nonce; this silently degrades "
            "to an unseeded commitment (e.g. two identical shares cancel). "
            "Regenerate shares with random_shares()."
        )
        raise ValueError(msg)
    commitment_hash, _ = create_commitment(content, nonce=joint)
    return commitment_hash, joint


def verify_threshold_commitment(
    commitment_hash: bytes,
    content: bytes,
    shares: Sequence[bytes],
) -> bool:
    """Verify a threshold-commitment reveal.

    Returns ``True`` iff reconstructing the joint nonce from
    ``shares`` and hashing ``content`` with it yields
    ``commitment_hash``. Returns ``False`` for malformed share sets
    (fewer than 2 shares, length mismatch) rather than raising; the
    underlying hash comparison is constant-time via
    :func:`synpareia.commitment.verify_commitment`.
    """
    if len(shares) < 2:
        return False
    try:
        joint = xor_shares(shares)
    except ValueError:
        return False
    return verify_commitment(commitment_hash, content, joint)
