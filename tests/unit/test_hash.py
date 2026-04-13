"""Tests for hashing and JCS canonicalization."""

from __future__ import annotations

import hashlib

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


class TestCanonicalHash:
    def test_returns_32_bytes(self) -> None:
        result = canonical_hash({"key": "value"})
        assert len(result) == 32

    def test_deterministic(self) -> None:
        obj = {"b": 2, "a": 1}
        assert canonical_hash(obj) == canonical_hash({"a": 1, "b": 2})
