"""SHA-256 hashing and RFC 8785 JSON Canonicalization Scheme (JCS)."""

from __future__ import annotations

import hashlib
from typing import Any

import rfc8785


def content_hash(data: bytes) -> bytes:
    """SHA-256 hash, returns 32 raw bytes."""
    return hashlib.sha256(data).digest()


def content_hash_hex(data: str) -> str:
    """SHA-256 of UTF-8 encoded string, returns hex digest."""
    return hashlib.sha256(data.encode()).hexdigest()


def jcs_canonicalize(obj: Any) -> bytes:
    """RFC 8785 JSON Canonicalization Scheme.

    Delegates to the ``rfc8785`` library for full RFC 8785 coverage:
    floats serialize per ECMAScript shortest-round-trip rules (so e.g.
    ``{"confidence": 0.7}`` is signable) and object keys sort in UTF-16
    code-unit order as the RFC requires.

    Output is byte-identical to the pre-0.6 home-rolled implementation
    over its accepted domain (str/int/bool/None/list/dict with ints in
    the I-JSON safe range and BMP-only keys) — existing hashes,
    signatures, and seals are unaffected. See
    ``tests/property/test_hash_properties.py::TestJCSDifferential``.

    Raises:
        TypeError: for values JCS cannot represent — non-JSON types,
            non-string dict keys, or strings containing lone surrogates.
        ValueError: for numbers outside the JCS domain — ints with
            magnitude >= 2**53 (``rfc8785.IntegerDomainError``) and
            NaN/infinity floats (``rfc8785.FloatDomainError``).
    """
    try:
        return rfc8785.dumps(obj)
    except (rfc8785.IntegerDomainError, rfc8785.FloatDomainError):
        # Load-bearing, not defensive: both are subclasses of
        # CanonicalizationError in rfc8785, so without this clause the
        # generic handler below would translate domain errors (ValueError)
        # into TypeError, breaking the documented contract.
        raise
    except rfc8785.CanonicalizationError as exc:
        # Preserve the historical contract (and json.dumps convention):
        # unsupported types raise TypeError.
        raise TypeError(str(exc)) from exc


def canonical_hash(obj: dict[str, Any]) -> bytes:
    """JCS canonicalize then SHA-256. Returns 32 raw bytes."""
    return content_hash(jcs_canonicalize(obj))
