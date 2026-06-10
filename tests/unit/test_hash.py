"""Tests for hashing and JCS canonicalization."""

from __future__ import annotations

import hashlib

import pytest

from synpareia.hash import canonical_hash, content_hash, content_hash_hex, jcs_canonicalize


class TestContentHash:
    def test_returns_32_bytes(self) -> None:
        result = content_hash(b"hello")
        assert len(result) == 32

    def test_matches_hashlib(self) -> None:
        data = b"test data"
        assert content_hash(data) == hashlib.sha256(data).digest()

    def test_content_hash_hex(self) -> None:
        result = content_hash_hex("hello")
        expected = hashlib.sha256(b"hello").hexdigest()
        assert result == expected


class TestJCS:
    def test_sorted_keys(self) -> None:
        obj = {"b": 1, "a": 2}
        result = jcs_canonicalize(obj)
        assert result == b'{"a":2,"b":1}'

    def test_nested_sorted_keys(self) -> None:
        obj = {"z": {"b": 1, "a": 2}, "a": 1}
        result = jcs_canonicalize(obj)
        assert result == b'{"a":1,"z":{"a":2,"b":1}}'

    def test_null_value(self) -> None:
        assert jcs_canonicalize(None) == b"null"

    def test_bool_values(self) -> None:
        assert jcs_canonicalize(True) == b"true"
        assert jcs_canonicalize(False) == b"false"

    def test_integer(self) -> None:
        assert jcs_canonicalize(42) == b"42"
        assert jcs_canonicalize(-1) == b"-1"

    def test_string(self) -> None:
        assert jcs_canonicalize("hello") == b'"hello"'

    def test_special_chars_in_string(self) -> None:
        result = jcs_canonicalize('line1\nline2\ttab"quote\\slash')
        assert result == b'"line1\\nline2\\ttab\\"quote\\\\slash"'

    def test_control_chars(self) -> None:
        result = jcs_canonicalize("\x00\x01\x1f")
        assert result == b'"\\u0000\\u0001\\u001f"'

    def test_unicode(self) -> None:
        result = jcs_canonicalize("café")
        assert result == '"café"'.encode()

    def test_list(self) -> None:
        result = jcs_canonicalize([1, "two", None])
        assert result == b'[1,"two",null]'

    def test_empty_dict(self) -> None:
        assert jcs_canonicalize({}) == b"{}"

    def test_empty_list(self) -> None:
        assert jcs_canonicalize([]) == b"[]"

    def test_no_whitespace(self) -> None:
        obj = {"a": [1, 2], "b": {"c": 3}}
        result = jcs_canonicalize(obj)
        assert b" " not in result
        assert b"\n" not in result


class TestJCSFloats:
    """Floats canonicalize per RFC 8785 (ECMAScript shortest round-trip).

    Previously a hard wall: the home-rolled implementation raised TypeError
    on any float, making e.g. ``{"confidence": 0.7}`` unsignable (audit D-8;
    bit the Witnessed-Prediction Form).
    """

    def test_simple_float(self) -> None:
        assert jcs_canonicalize(0.7) == b"0.7"
        assert jcs_canonicalize({"confidence": 0.7}) == b'{"confidence":0.7}'

    def test_ecmascript_serialization(self) -> None:
        # Shortest-round-trip forms per RFC 8785 §3.2.2.3 / ECMAScript
        assert jcs_canonicalize(0.5) == b"0.5"
        assert jcs_canonicalize(1e21) == b"1e+21"
        assert jcs_canonicalize(1e-7) == b"1e-7"
        assert jcs_canonicalize(-0.0) == b"0"
        assert jcs_canonicalize(2.0) == b"2"

    def test_nan_and_infinity_raise_value_error(self) -> None:
        for bad in (float("nan"), float("inf"), float("-inf")):
            with pytest.raises(ValueError):
                jcs_canonicalize(bad)


class TestJCSDomainErrors:
    def test_safe_integer_bounds(self) -> None:
        # I-JSON safe range is representable...
        assert jcs_canonicalize(2**53 - 1) == b"9007199254740991"
        assert jcs_canonicalize(-(2**53) + 1) == b"-9007199254740991"
        # ...and beyond it ints raise ValueError (rfc8785.IntegerDomainError).
        # The legacy implementation accepted these but emitted RFC-violating
        # bytes; rfc8785 fails loudly instead — acceptance->exception only,
        # never silently different bytes.
        for bad_int in (2**53, -(2**53), 2**60):
            with pytest.raises(ValueError):
                jcs_canonicalize(bad_int)

    def test_unsupported_types_still_raise_type_error(self) -> None:
        # Historical contract (mirrors json.dumps): TypeError on non-JSON types.
        for bad in ({1, 2}, b"bytes", object()):
            with pytest.raises(TypeError):
                jcs_canonicalize(bad)

    def test_non_string_dict_key_raises_type_error(self) -> None:
        with pytest.raises(TypeError):
            jcs_canonicalize({1: "int key"})

    def test_lone_surrogate_raises_type_error(self) -> None:
        # Previously UnicodeEncodeError; now TypeError via the
        # CanonicalizationError translation. Still rejected, just typed.
        with pytest.raises(TypeError):
            jcs_canonicalize("\ud800")


class TestJCSKeyOrdering:
    def test_supplementary_plane_keys_sort_by_utf16_code_units(self) -> None:
        """RFC 8785 §3.2.3: keys sort by UTF-16 code units, not code points.

        U+1F600 encodes as surrogate pair D83D DE00; D83D < E000 < FFFF, so
        the emoji key sorts *first* — code-point order would put it last.
        The legacy implementation got this wrong (audit D-8 RFC drift).
        """
        obj = {"\U0001f600": 1, "￿": 2, "": 3}
        result = jcs_canonicalize(obj)
        assert result == '{"\U0001f600":1,"":3,"￿":2}'.encode()

    def test_bmp_keys_unchanged_by_swap(self) -> None:
        # For BMP-only keys, UTF-16 code-unit order == code-point order:
        # exactly what the legacy implementation produced.
        obj = {"דּ": 1, "z": 2, "é": 3}
        assert jcs_canonicalize(obj) == '{"z":2,"é":3,"דּ":1}'.encode()


class TestCanonicalHash:
    def test_returns_32_bytes(self) -> None:
        result = canonical_hash({"key": "value"})
        assert len(result) == 32

    def test_deterministic(self) -> None:
        obj = {"b": 2, "a": 1}
        assert canonical_hash(obj) == canonical_hash({"a": 1, "b": 2})


def test_integral_float_beyond_safe_range_is_non_idempotent() -> None:
    """Pin the rfc8785 behavioral trap (PR #247 review, medium finding).

    ``2.0**53`` canonicalizes successfully to integer-looking bytes (valid
    ECMAScript shortest form), but re-parsing those bytes yields an int
    outside the I-JSON safe range, which the integer guard rejects — so a
    payload containing such a float signs fine yet cannot be re-canonicalized
    after a JSON round-trip. If a future rfc8785 version changes either side
    of this (starts rejecting the float, or accepting the int), this test
    fails and the exception contract + docs must be revisited.
    """
    import json as _json

    out = jcs_canonicalize(2.0**53)
    assert out == b"9007199254740992"
    with pytest.raises(ValueError):
        jcs_canonicalize(_json.loads(out))
