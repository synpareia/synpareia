"""Regression tests for findings from close-read 2026-04-30 (publish gate).

Coverage:
- E9 (HIGH): SyncWitnessClient no longer uses deprecated asyncio.get_event_loop;
  instead uses asyncio.run() — verified by source-grep, since execution is
  identical and the deprecation is a static signal.
- AmendmentRules (MEDIUM): override whose path is literally "default" no longer
  collides with the rule's own default field; nested-overrides serialization.
- from_public_key (LOW): rejects non-32-byte input early instead of deferring
  to first-verify.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import synpareia
from synpareia.policy import (
    AmendmentOverride,
    AmendmentRules,
)
from synpareia.policy.serialize import (
    _amendment_rules_from_dict,
    _amendment_rules_to_dict,
)

# ---------------------------------------------------------------------------
# E9 — asyncio.get_event_loop deprecation no longer present
# ---------------------------------------------------------------------------


def test_e9_no_get_event_loop_in_sync_witness_client() -> None:
    """SyncWitnessClient should use asyncio.run, not the deprecated get_event_loop."""
    src = Path(__file__).resolve().parents[2] / "src" / "synpareia" / "witness" / "client.py"
    text = src.read_text()
    assert "asyncio.get_event_loop()" not in text
    # Sanity: asyncio.run is the replacement.
    assert "asyncio.run(" in text


# ---------------------------------------------------------------------------
# AmendmentRules — "default" path collision
# ---------------------------------------------------------------------------


def test_amendment_rules_override_named_default_round_trips() -> None:
    """An override whose path is literally 'default' must survive round-trip."""
    rules = AmendmentRules(
        default="all_signatories_cosign",
        overrides=(
            AmendmentOverride(path="default", requirement="owner_decides"),
            AmendmentOverride(path="signatories.add", requirement="quorum"),
        ),
    )
    serialized = _amendment_rules_to_dict(rules)
    restored = _amendment_rules_from_dict(serialized)

    # The 'default' override must survive the round-trip — it doesn't collide
    # with the AmendmentRules.default field because overrides are nested.
    assert restored.default == "all_signatories_cosign"
    paths = {ov.path for ov in restored.overrides}
    assert "default" in paths
    assert "signatories.add" in paths
    requirements = {ov.path: ov.requirement for ov in restored.overrides}
    assert requirements["default"] == "owner_decides"
    assert requirements["signatories.add"] == "quorum"


def test_amendment_rules_serialization_uses_nested_overrides() -> None:
    """The new serialization shape nests overrides under 'overrides'."""
    rules = AmendmentRules(
        default="quorum",
        overrides=(AmendmentOverride(path="x", requirement="y"),),
    )
    serialized = _amendment_rules_to_dict(rules)
    assert serialized == {"default": "quorum", "overrides": {"x": "y"}}


def test_amendment_rules_reads_old_flat_shape_for_backward_compat() -> None:
    """Pre-0.3.1 serialized data used flat siblings; that path must still read."""
    legacy = {
        "default": "all_signatories_cosign",
        "x.path": "owner_decides",
        "y.path": "quorum",
    }
    restored = _amendment_rules_from_dict(legacy)
    assert restored.default == "all_signatories_cosign"
    paths = {ov.path: ov.requirement for ov in restored.overrides}
    assert paths == {"x.path": "owner_decides", "y.path": "quorum"}


def test_amendment_rules_empty_overrides_produces_compact_dict() -> None:
    rules = AmendmentRules(default="quorum")
    serialized = _amendment_rules_to_dict(rules)
    # No overrides key when empty; keeps the wire format compact.
    assert serialized == {"default": "quorum"}
    restored = _amendment_rules_from_dict(serialized)
    assert restored == rules


# ---------------------------------------------------------------------------
# from_public_key — 32-byte validation
# ---------------------------------------------------------------------------


def test_from_public_key_rejects_short_bytes() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        synpareia.from_public_key(b"too short")


def test_from_public_key_rejects_long_bytes() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        synpareia.from_public_key(b"\x00" * 64)


def test_from_public_key_rejects_non_bytes() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        synpareia.from_public_key("not-bytes")  # type: ignore[arg-type]


def test_from_public_key_accepts_32_bytes() -> None:
    """Sanity: the 32-byte happy path still works."""
    profile = synpareia.generate()
    public_only = synpareia.from_public_key(profile.public_key)
    assert public_only.id == profile.id
    assert public_only.public_key == profile.public_key
    assert public_only.private_key is None
