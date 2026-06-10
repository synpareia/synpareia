"""Read-time served-value layer over the channel model: clamp + negative weighting.

Design grounding (topology-erasure-design.md §4 rule 3; topology-function-contracts.md §4):
- Stored accumulators stay RAW/LINEAR (per-channel ``Moment`` sums); clamp is read-only.
- Served valence is the valence channel's **magnitude** ``Σw·v / Σw`` (a weighted
  mean of the values), clamped to ``[-1, 1]`` at read. Familiarity (the interaction
  channel's backing ``Σw``) is unclamped (monotonic ≥ 0).
- Negative-signal weighting (production-design §3, RepuNet #4): the 1.5× scales the
  *value* ``v`` (decision 2026-06-08), not the weight ``w`` — so a strong negative
  lands at ``v`` below ``-1`` (which is exactly why the read-time clamp exists),
  while the backing/confidence ``Σw`` stays honest. Linear, so erasure is exact.
- Decay is read-time too but is NOT in the minimal cut (deferred).
"""

from __future__ import annotations

import pytest

from synpareia.topology import (
    NEGATIVE_VALENCE_WEIGHT,
    clamp_valence,
    negative_valence_value,
)
from synpareia.topology.store import TopologyStore

# ---------------------------------------------------------------------------
# Read-time clamp (served valence magnitude ∈ [-1, 1]; familiarity unclamped)
# ---------------------------------------------------------------------------


def test_served_valence_magnitude_is_clamped_at_read_high() -> None:
    store = TopologyStore()
    # two events whose values average above the ceiling: mean(1.6, 1.6) = 1.6
    store.update_valence("did:a", "did:b", 1.0, 1.6, at=1.0, event_hash="e1", subject_did="did:b")
    store.update_valence("did:a", "did:b", 1.0, 1.6, at=2.0, event_hash="e2", subject_did="did:b")
    edge = store.get_served_edge("did:a", "did:b")
    assert edge is not None
    _, valence = edge
    assert valence == pytest.approx(1.0)  # clamped, not 1.6


def test_served_valence_magnitude_is_clamped_at_read_low() -> None:
    store = TopologyStore()
    # negative weighting pushes v below -1: negative_valence_value(0.9) = -1.35
    v = negative_valence_value(0.9)
    store.update_valence("did:a", "did:b", 1.0, v, at=1.0, event_hash="e1", subject_did="did:b")
    edge = store.get_served_edge("did:a", "did:b")
    assert edge is not None
    _, valence = edge
    assert valence == pytest.approx(-1.0)  # clamped, not -1.35


def test_raw_stored_magnitude_is_not_clamped() -> None:
    """Design rule 3: storage stays linear/unclamped — only the read view clamps.
    Raw served valence is the unclamped weighted-mean magnitude."""
    store = TopologyStore()
    store.update_valence("did:a", "did:b", 1.0, 1.6, at=1.0, event_hash="e1", subject_did="did:b")
    raw = store.get_edge("did:a", "did:b")  # raw (Slice-1) accessor
    assert raw is not None
    _, raw_valence = raw
    assert raw_valence == pytest.approx(1.6)  # unclamped magnitude


def test_valence_magnitude_is_a_backing_weighted_mean() -> None:
    """Magnitude = Σw·v / Σw — a weighted mean of the values, not a sum. Heavier
    events pull the mean more."""
    store = TopologyStore()
    store.update_valence("did:a", "did:b", 1.0, 0.2, at=1.0, event_hash="e1", subject_did="did:b")
    store.update_valence("did:a", "did:b", 3.0, 1.0, at=2.0, event_hash="e2", subject_did="did:b")
    raw = store.get_edge("did:a", "did:b")
    assert raw is not None
    # (1*0.2 + 3*1.0) / (1 + 3) = 3.2 / 4 = 0.8
    assert raw[1] == pytest.approx(0.8)


def test_familiarity_served_is_unclamped() -> None:
    store = TopologyStore()
    for i in range(5):
        store.record_co_interaction("did:a", "did:b", weight=1.0, at=float(i), event_hash=f"co{i}")
    edge = store.get_served_edge("did:a", "did:b")
    assert edge is not None
    familiarity, _ = edge
    assert familiarity == pytest.approx(5.0)  # no ceiling on familiarity (interaction Σw)


def test_served_edge_none_for_missing() -> None:
    store = TopologyStore()
    assert store.get_served_edge("did:a", "did:b") is None


def test_edges_for_serves_clamped_valence() -> None:
    """EdgeView is the served neighbour projection — its valence (magnitude) is
    clamped, its familiarity (interaction backing) is not."""
    store = TopologyStore()
    store.update_valence("did:a", "did:b", 1.0, 1.6, at=1.0, event_hash="e1", subject_did="did:b")
    store.record_co_interaction("did:a", "did:b", weight=3.0, at=3.0, event_hash="co")
    views = store.edges_for("did:a")
    assert len(views) == 1
    assert views[0].valence == pytest.approx(1.0)  # clamped, not 1.6
    assert views[0].familiarity == pytest.approx(3.0)  # unclamped backing


def test_clamp_after_erasure_reflects_remaining() -> None:
    """Read-time clamp composes with erasure: after erasing a revocable event,
    the served (clamped) magnitude reflects what remains."""
    store = TopologyStore()
    store.update_valence(
        "did:a", "did:b", 1.0, 1.6, at=1.0, event_hash="rev", subject_did="did:b", revocable=True
    )
    store.update_valence(
        "did:a", "did:b", 1.0, 0.8, at=2.0, event_hash="nr", subject_did="did:b", revocable=False
    )
    # magnitude = (1*1.6 + 1*0.8)/2 = 1.2 -> served clamps to 1.0
    assert store.get_served_edge("did:a", "did:b")[1] == pytest.approx(1.0)  # type: ignore[index]
    store.erase_contributions("did:b")  # drop the revocable event
    # remaining = non-revocable (w=1, v=0.8) -> magnitude 0.8, no longer clamped
    assert store.get_served_edge("did:a", "did:b")[1] == pytest.approx(0.8)  # type: ignore[index]


# ---------------------------------------------------------------------------
# Negative-signal weighting (value-side linear scaling)
# ---------------------------------------------------------------------------


def test_negative_valence_weight_is_pinned_at_1_5() -> None:
    assert NEGATIVE_VALENCE_WEIGHT == 1.5


def test_negative_valence_value_scales_the_value() -> None:
    # a base negative signal of 0.4 becomes value v = -0.6 (1.5x)
    assert negative_valence_value(0.4) == pytest.approx(-0.6)


def test_negative_value_is_still_linear_so_erasure_exact() -> None:
    """The weighted negative value feeds Σw·v linearly, so contribution-subtract
    still recovers the pre-event accumulator exactly."""
    store = TopologyStore()
    store.update_valence("did:a", "did:b", 1.0, 0.5, at=1.0, event_hash="pos", subject_did="did:b")
    store.update_valence(
        "did:a",
        "did:b",
        1.0,
        negative_valence_value(0.4),  # v = -0.6
        at=2.0,
        event_hash="neg",
        subject_did="did:b",
        revocable=True,
    )
    raw = store.get_edge("did:a", "did:b")
    assert raw is not None
    # magnitude = (1*0.5 + 1*(-0.6)) / (1+1) = -0.05
    assert raw[1] == pytest.approx(-0.05)
    store.erase_contributions("did:b")  # removes both (subject did:b, revocable)
    # edge record persists (no whole-edge-deletion, design rule 2); valence magnitude
    # is back to 0.0 (no backing) — exactly the pre-event state.
    assert store.get_edge("did:a", "did:b")[1] == pytest.approx(0.0)  # type: ignore[index]


def test_negative_valence_value_rejects_negative_magnitude() -> None:
    with pytest.raises(ValueError, match="non-negative base magnitude"):
        negative_valence_value(-0.1)


def test_negative_valence_value_rejects_non_finite_magnitude() -> None:
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError, match="finite non-negative base magnitude"):
            negative_valence_value(bad)


# ---------------------------------------------------------------------------
# clamp_valence unit + non-finite write-time guards
# ---------------------------------------------------------------------------


def test_clamp_valence_boundaries() -> None:
    assert clamp_valence(-1.0) == -1.0
    assert clamp_valence(1.0) == 1.0
    assert clamp_valence(0.3) == pytest.approx(0.3)
    assert clamp_valence(2.5) == 1.0
    assert clamp_valence(-2.5) == -1.0
    assert clamp_valence(float("inf")) == 1.0
    assert clamp_valence(float("-inf")) == -1.0


def test_clamp_valence_rejects_nan() -> None:
    with pytest.raises(ValueError, match="NaN"):
        clamp_valence(float("nan"))


def test_update_valence_rejects_non_finite_value() -> None:
    """Non-finite values are rejected at the source: inf would saturate Σw·v
    irreversibly, and NaN would slip through the read-time clamp."""
    store = TopologyStore()
    for bad in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError, match="valence value v must be finite"):
            store.update_valence("did:a", "did:b", 1.0, bad, at=1.0)


def test_update_valence_rejects_negative_weight() -> None:
    """The backing weight w must be finite and non-negative (it is evidence mass)."""
    store = TopologyStore()
    for bad in (-1.0, float("inf")):
        with pytest.raises(ValueError, match="valence weight w"):
            store.update_valence("did:a", "did:b", bad, 0.5, at=1.0)
