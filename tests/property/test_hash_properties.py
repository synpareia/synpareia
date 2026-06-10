"""Property-based tests for hashing.

Includes the hash-compatibility differential suite for the rfc8785 swap
(launch hit-list 1.4 / audit D-8): ``_legacy_jcs`` below is a verbatim
reference copy of the pre-0.6 home-rolled canonicalizer, and
``TestJCSDifferential`` proves byte-identity between it and the
library-backed ``jcs_canonicalize`` over the legacy implementation's
accepted domain. Existing chain/seal/signature hashes therefore verify
unchanged.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from synpareia.hash import canonical_hash, content_hash, jcs_canonicalize


class TestHashProperties:
    @given(st.binary(min_size=1, max_size=10000))
    def test_content_hash_deterministic(self, data: bytes) -> None:
        assert content_hash(data) == content_hash(data)

    @given(st.binary(min_size=1, max_size=10000))
    def test_content_hash_is_32_bytes(self, data: bytes) -> None:
        assert len(content_hash(data)) == 32

    @given(
        st.binary(min_size=1, max_size=1000),
        st.binary(min_size=1, max_size=1000),
    )
    def test_different_content_different_hash(self, a: bytes, b: bytes) -> None:
        if a != b:
            assert content_hash(a) != content_hash(b)


# ---------------------------------------------------------------------------
# Legacy reference implementation (pre-rfc8785 jcs_canonicalize, verbatim).
# Kept here solely as the differential-test oracle. Its accepted domain:
# str/int/bool/None/list/dict; arbitrary-precision ints; keys sorted by
# code point (correct for BMP-only keys, RFC-divergent above U+FFFF).
# ---------------------------------------------------------------------------


def _legacy_jcs(obj: Any) -> bytes:
    return _legacy_serialize(obj).encode()


def _legacy_serialize(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return _legacy_serialize_string(value)
    if isinstance(value, list):
        items = ",".join(_legacy_serialize(item) for item in value)
        return f"[{items}]"
    if isinstance(value, dict):
        sorted_keys = sorted(value.keys())
        pairs = ",".join(
            f"{_legacy_serialize_string(k)}:{_legacy_serialize(value[k])}" for k in sorted_keys
        )
        return f"{{{pairs}}}"
    msg = f"Unsupported type for JCS: {type(value)}"
    raise TypeError(msg)


def _legacy_serialize_string(s: str) -> str:
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


# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# I-JSON safe-integer range: the intersection of the legacy domain (any int)
# and the RFC 8785 domain enforced by rfc8785 (|n| <= 2**53 - 1).
SAFE_INT_MAX = 2**53 - 1

safe_ints = st.integers(min_value=-SAFE_INT_MAX, max_value=SAFE_INT_MAX)

# st.text() excludes surrogates by default; this covers the full assigned
# Unicode range including supplementary planes (legacy passed those through
# unescaped in *values*, identically to rfc8785).
any_text = st.text(max_size=200)

# Keys restricted to the BMP: the one place legacy ordering (code point)
# and RFC 8785 ordering (UTF-16 code units) provably coincide.
bmp_keys = st.text(
    alphabet=st.characters(max_codepoint=0xFFFF, exclude_categories=("Cs",)),
    max_size=30,
)

# The legacy implementation's accepted domain (no floats, BMP-only keys).
legacy_domain_primitives = st.one_of(any_text, safe_ints, st.booleans(), st.none())
legacy_domain_values = st.recursive(
    legacy_domain_primitives,
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(bmp_keys, children, max_size=5),
    ),
    max_leaves=25,
)

# The full post-swap domain: adds finite floats and supplementary-plane keys.
# Integral floats beyond the safe-int range are excluded: rfc8785 serializes
# e.g. 2.0**53 as "9007199254740992" (valid ECMAScript), but that parses back
# as an int that rfc8785's I-JSON integer guard rejects — so the JSON
# round-trip (and hence the idempotency property) doesn't hold for them.
json_floats = st.floats(allow_nan=False, allow_infinity=False).filter(
    lambda f: not (f.is_integer() and abs(f) > SAFE_INT_MAX)
)
json_primitives = st.one_of(
    any_text,
    safe_ints,
    json_floats,
    st.booleans(),
    st.none(),
)
json_values = st.recursive(
    json_primitives,
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(any_text, children, max_size=5),
    ),
    max_leaves=25,
)
json_dicts = st.dictionaries(any_text, json_values, max_size=10)


class TestJCSDifferential:
    """Byte-identity of rfc8785-backed jcs_canonicalize vs the legacy code.

    This is the hash-compatibility proof for the swap: over everything the
    legacy implementation accepted *and serialized per the RFC* (BMP-only
    keys, safe-range ints, no floats), the bytes — and therefore every
    derived hash and signature — are identical.
    """

    @given(legacy_domain_values)
    def test_byte_identical_on_legacy_domain(self, obj: object) -> None:
        assert jcs_canonicalize(obj) == _legacy_jcs(obj)

    @given(st.dictionaries(bmp_keys, legacy_domain_values, max_size=10))
    def test_canonical_hash_identical_on_legacy_domain(self, obj: dict[str, Any]) -> None:
        assert canonical_hash(obj) == content_hash(_legacy_jcs(obj))

    @given(st.integers(min_value=2**53, max_value=2**60))
    def test_known_divergence_out_of_range_ints_now_raise(self, n: int) -> None:
        """The one divergence on the legacy-accepted domain, characterized.

        Legacy serialized ints of any magnitude via str() — output that
        violates RFC 8785 (which requires IEEE-754 double / ECMAScript
        number serialization) for |n| >= 2**53. rfc8785 rejects these
        loudly instead. Acceptance -> exception only: no input yields
        *different bytes*, so nothing can silently re-hash.
        """
        assert _legacy_jcs(n) == str(n).encode()  # legacy accepted (RFC-invalid)
        for value in (n, -n):
            with pytest.raises(ValueError):
                jcs_canonicalize(value)


class TestJCSProperties:
    @given(json_values)
    def test_jcs_idempotent(self, obj: object) -> None:
        """Canonicalizing twice gives the same result."""
        first = jcs_canonicalize(obj)
        parsed = json.loads(first)
        second = jcs_canonicalize(parsed)
        assert first == second

    @given(json_dicts)
    def test_canonical_hash_deterministic(self, obj: dict[str, object]) -> None:
        assert canonical_hash(obj) == canonical_hash(obj)

    @given(st.dictionaries(any_text, json_values, min_size=1, max_size=10))
    def test_jcs_produces_valid_json(self, obj: dict[str, object]) -> None:
        result = jcs_canonicalize(obj)
        parsed = json.loads(result)
        assert isinstance(parsed, dict)
