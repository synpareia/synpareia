"""SHA-256 hashing and RFC 8785 JSON Canonicalization Scheme (JCS)."""

from __future__ import annotations

import hashlib
from typing import Any


def content_hash(data: bytes) -> bytes:
    """SHA-256 hash, returns 32 raw bytes."""
    return hashlib.sha256(data).digest()


def content_hash_hex(data: str) -> str:
    """SHA-256 of UTF-8 encoded string, returns hex digest."""
    return hashlib.sha256(data.encode()).hexdigest()


def jcs_canonicalize(obj: Any) -> bytes:
    """RFC 8785 JSON Canonicalization Scheme.

    Minimal implementation covering strings, ints, bools, None, lists, and dicts.
    No float support needed in our domain.
    """
    return _serialize(obj).encode()


def canonical_hash(obj: dict[str, Any]) -> bytes:
    """JCS canonicalize then SHA-256. Returns 32 raw bytes."""
    return content_hash(jcs_canonicalize(obj))


def _serialize(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return _serialize_string(value)
    if isinstance(value, list):
        items = ",".join(_serialize(item) for item in value)
        return f"[{items}]"
    if isinstance(value, dict):
        # RFC 8785: keys sorted by Unicode code point order
        sorted_keys = sorted(value.keys())
        pairs = ",".join(f"{_serialize_string(k)}:{_serialize(value[k])}" for k in sorted_keys)
        return f"{{{pairs}}}"
    msg = f"Unsupported type for JCS: {type(value)}"
    raise TypeError(msg)


def _serialize_string(s: str) -> str:
    """JSON string serialization with required escapes per RFC 8785."""
    result = ['"']
    for ch in s:
        cp = ord(ch)
        if ch == '"':
            result.append('\\"')
        elif ch == "\\":
            result.append("\\\\")
        elif ch == "\b":
            result.append("\\b")
        elif ch == "\f":
            result.append("\\f")
        elif ch == "\n":
            result.append("\\n")
        elif ch == "\r":
            result.append("\\r")
        elif ch == "\t":
            result.append("\\t")
        elif cp < 0x20:
            result.append(f"\\u{cp:04x}")
        else:
            result.append(ch)
    result.append('"')
    return "".join(result)
