"""Property-based tests for hashing."""

from __future__ import annotations

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


# Strategy for JSON-compatible values (no floats)
json_primitives = st.one_of(
    st.text(max_size=50),
    st.integers(min_value=-(2**53), max_value=2**53),
    st.booleans(),
    st.none(),
)

json_values = st.recursive(
    json_primitives,
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(st.text(max_size=10), children, max_size=5),
    ),
    max_leaves=20,
)


class TestJCSProperties:
    @given(st.dictionaries(st.text(max_size=20), json_primitives, max_size=10))
    def test_jcs_idempotent(self, obj: dict[str, object]) -> None:
        """Canonicalizing twice gives the same result."""
        first = jcs_canonicalize(obj)
        # Parse the result and re-canonicalize
        import json

        parsed = json.loads(first)
        second = jcs_canonicalize(parsed)
        assert first == second

    @given(st.dictionaries(st.text(max_size=20), json_primitives, max_size=10))
    def test_canonical_hash_deterministic(self, obj: dict[str, object]) -> None:
        assert canonical_hash(obj) == canonical_hash(obj)

    @given(st.dictionaries(st.text(max_size=20), json_primitives, min_size=1, max_size=10))
    def test_jcs_produces_valid_json(self, obj: dict[str, object]) -> None:
        import json

        result = jcs_canonicalize(obj)
        parsed = json.loads(result)
        assert isinstance(parsed, dict)
