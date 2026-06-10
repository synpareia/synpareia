"""Slice 1 — uniform per-channel accumulators + contribution ledger + erasure.

Encodes the design rules from docs/explorations/topology-erasure-design.md §9:
1. Locality — events mutate only edges among their own parties.
2. No whole-edge deletion — erasure is sub-edge (contribution-subtract / bucket-zero).
3. Stored accumulator linear (the channel ``Moment`` sums; clamp/decay are read-time).
4. Non-revocability — the non-revocable bucket survives erasure.
5. Additive-decomposable — contribution-subtract removes exactly one event's moment.

Channel model: each characteristic is a channel with a ``Moment`` ``(Σw, Σw·v)``
per direction/bucket. Familiarity is the symmetric ``interaction`` channel's
backing ``Σw``; valence is a directional channel whose served value is the
magnitude ``Σw·v / Σw``. With ``w = 1`` per valence event, a bucket's magnitude
equals the mean of its values (so single-event buckets read as the value ``v``).
"""

from __future__ import annotations

import pytest

from synpareia.topology import INTERACTION_CHANNEL, VALENCE_CHANNEL
from synpareia.topology.model import EdgePair
from synpareia.topology.store import TopologyStore

# ---------------------------------------------------------------------------
# Per-channel two-bucket model
# ---------------------------------------------------------------------------


def test_edgepair_starts_empty() -> None:
    pair = EdgePair.new("did:a", "did:b")
    assert pair.served_valence("did:a", "did:b") == 0.0
    assert pair.served_familiarity("did:a", "did:b") == 0.0


def test_served_value_combines_both_buckets() -> None:
    """Served valence is a backing-weighted mean over both buckets (not a sum)."""
    pair = EdgePair.new("did:a", "did:b")
    pair = pair.with_channel_event(
        VALENCE_CHANNEL, "did:a", "did:b", 1.0, 0.3, 1.0, revocable=True
    )
    pair = pair.with_channel_event(
        VALENCE_CHANNEL, "did:a", "did:b", 1.0, 0.4, 2.0, revocable=False
    )
    # magnitude = (1*0.3 + 1*0.4) / (1+1) = 0.35
    assert pair.served_valence("did:a", "did:b") == pytest.approx(0.35)


def test_buckets_are_independently_addressable() -> None:
    pair = EdgePair.new("did:a", "did:b")
    pair = pair.with_channel_event(
        VALENCE_CHANNEL, "did:a", "did:b", 1.0, 0.3, 1.0, revocable=True
    )
    pair = pair.with_channel_event(
        VALENCE_CHANNEL, "did:a", "did:b", 1.0, 0.5, 2.0, revocable=False
    )
    assert pair.revocable_valence("did:a", "did:b") == pytest.approx(0.3)
    assert pair.non_revocable_valence("did:a", "did:b") == pytest.approx(0.5)


def test_valence_direction_is_asymmetric_across_buckets() -> None:
    pair = EdgePair.new("did:a", "did:b")
    pair = pair.with_channel_event(
        VALENCE_CHANNEL, "did:a", "did:b", 1.0, 0.3, 1.0, revocable=True
    )
    assert pair.served_valence("did:a", "did:b") == pytest.approx(0.3)
    assert pair.served_valence("did:b", "did:a") == 0.0  # reverse direction untouched


def test_familiarity_symmetric_within_a_bucket() -> None:
    pair = EdgePair.new("did:a", "did:b")
    pair = pair.with_channel_event(
        INTERACTION_CHANNEL, "did:a", "did:b", 1.0, 0.0, 1.0, revocable=True
    )
    # co-occurrence is symmetric: both directions get the backing
    assert pair.served_familiarity("did:a", "did:b") == pytest.approx(1.0)
    assert pair.served_familiarity("did:b", "did:a") == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# Contribution ledger + erasure (store level)
# ---------------------------------------------------------------------------


def _seed(store: TopologyStore) -> None:
    """A and B interact (revocable); A→B valence revocable + non-revocable."""
    store.record_co_interaction(
        "did:a", "did:b", weight=1.0, at=1.0, event_hash="ev1", subject_did="did:a", revocable=True
    )
    store.update_valence(
        "did:a", "did:b", 1.0, 0.4, at=2.0, event_hash="ev2", subject_did="did:b", revocable=True
    )
    store.update_valence(
        "did:a", "did:b", 1.0, 0.6, at=3.0, event_hash="ev3", subject_did="did:b", revocable=False
    )


def test_erase_subtracts_only_subjects_revocable_contributions() -> None:
    store = TopologyStore()
    _seed(store)
    before = store.get_edge("did:a", "did:b")
    assert before is not None
    _, val_before = before
    # magnitude = (0.4 rev + 0.6 non_revocable) / 2 events = 0.5
    assert val_before == pytest.approx(0.5)

    store.erase_contributions("did:b")

    after = store.get_edge("did:a", "did:b")
    assert after is not None
    _, val_after = after
    # revocable valence (ev2) gone; non_revocable (ev3, w=1, v=0.6) survives -> magnitude 0.6
    assert val_after == pytest.approx(0.6)


def test_nonrevocable_survives_erasure() -> None:
    store = TopologyStore()
    _seed(store)
    store.erase_contributions("did:b")
    pair = store.get_pair("did:a", "did:b")
    assert pair is not None
    assert pair.non_revocable_valence("did:a", "did:b") == pytest.approx(0.6)


def test_erase_is_idempotent_via_hash_dedup() -> None:
    store = TopologyStore()
    _seed(store)
    store.erase_contributions("did:b")
    first = store.get_edge("did:a", "did:b")
    store.erase_contributions("did:b")  # replay — must not double-subtract
    second = store.get_edge("did:a", "did:b")
    assert first == second


def test_ingest_is_idempotent_via_hash_dedup() -> None:
    store = TopologyStore()
    store.update_valence(
        "did:a", "did:b", 1.0, 0.4, at=1.0, event_hash="dup", subject_did="did:b", revocable=True
    )
    store.update_valence(
        "did:a", "did:b", 1.0, 0.4, at=1.0, event_hash="dup", subject_did="did:b", revocable=True
    )
    edge = store.get_edge("did:a", "did:b")
    assert edge is not None
    _, val = edge
    assert val == pytest.approx(0.4)  # second ingest of same hash is a no-op


def test_locality_erasing_subject_touches_only_their_edges() -> None:
    store = TopologyStore()
    store.update_valence(
        "did:a", "did:b", 1.0, 0.5, at=1.0, event_hash="ab", subject_did="did:b", revocable=True
    )
    store.update_valence(
        "did:c", "did:d", 1.0, 0.7, at=1.0, event_hash="cd", subject_did="did:d", revocable=True
    )
    store.erase_contributions("did:b")
    cd = store.get_edge("did:c", "did:d")
    assert cd is not None
    assert cd[1] == pytest.approx(0.7)  # untouched


def test_erase_is_channel_and_subject_scoped() -> None:
    """Channel-keyed erasure makes mis-subtraction structurally impossible: a
    contribution names its channel and subtraction hits that channel's cell only.
    Combined with subject-scoping, erasing one party's data leaves the other
    channel/party's data intact — no cross-channel corruption."""
    store = TopologyStore()
    # co-occurrence (interaction): data about BOTH a and b
    store.record_co_interaction(
        "did:a", "did:b", weight=2.0, at=1.0, event_hash="co", revocable=True
    )
    # A's valence about B (valence channel): data about b only
    store.update_valence(
        "did:a", "did:b", 1.0, 0.4, at=2.0, event_hash="val", subject_did="did:b", revocable=True
    )
    store.erase_contributions("did:a")  # a is a subject of the co-occurrence only
    fam, val = store.get_edge("did:a", "did:b")  # type: ignore[misc]
    assert fam == pytest.approx(0.0)  # interaction (about a&b) erased
    assert val == pytest.approx(0.4)  # valence-about-b (a not a subject) survives


def test_zero_revocable_bucket_fallback() -> None:
    """Posture-3 fallback: zero the whole revocable bucket of one edge (all
    channels), non-revocable untouched. Works for any update rule."""
    store = TopologyStore()
    _seed(store)
    store.zero_revocable_bucket("did:a", "did:b")
    pair = store.get_pair("did:a", "did:b")
    assert pair is not None
    assert pair.revocable_valence("did:a", "did:b") == 0.0
    assert pair.revocable_familiarity("did:a", "did:b") == 0.0
    assert pair.non_revocable_valence("did:a", "did:b") == pytest.approx(0.6)


def test_whole_edge_deletion_is_not_exposed() -> None:
    """Rule 2: there is no public 'delete this edge' operation on the store."""
    store = TopologyStore()
    assert not hasattr(store, "delete_edge")
    assert not hasattr(store, "delete_pair")
    assert not hasattr(store, "remove_edge")


# ---------------------------------------------------------------------------
# Locality enforcement (design rule 1 — the one hard rule)
# ---------------------------------------------------------------------------


def test_valence_subject_rejected_when_not_target() -> None:
    # For valence the subject must be the TARGET (stricter than 'a party'); a
    # non-target subject_did is rejected (closes the laundering hole).
    store = TopologyStore()
    with pytest.raises(ValueError, match="valence target"):
        store.update_valence(
            "did:a",
            "did:b",
            1.0,
            0.5,
            at=1.0,
            event_hash="ev",
            subject_did="did:x",
            revocable=True,
        )


def test_subject_did_must_be_a_party_familiarity() -> None:
    store = TopologyStore()
    with pytest.raises(ValueError, match="locality invariant"):
        store.record_co_interaction(
            "did:a", "did:b", weight=1.0, at=1.0, event_hash="ev", subject_did="did:x"
        )


# ---------------------------------------------------------------------------
# Familiarity erasure + dual-subject co-occurrence
# ---------------------------------------------------------------------------


def test_familiarity_erasure_by_either_party() -> None:
    """Co-occurrence familiarity is about BOTH parties — either one's erasure
    removes the shared fact."""
    store = TopologyStore()
    store.record_co_interaction(
        "did:a", "did:b", weight=2.0, at=1.0, event_hash="co1", revocable=True
    )
    assert store.get_edge("did:a", "did:b") == pytest.approx((2.0, 0.0))
    store.erase_contributions("did:b")
    assert store.get_edge("did:a", "did:b") == pytest.approx((0.0, 0.0))


def test_familiarity_erasure_idempotent_across_both_subjects() -> None:
    store = TopologyStore()
    store.record_co_interaction(
        "did:a", "did:b", weight=2.0, at=1.0, event_hash="co1", revocable=True
    )
    assert store.erase_contributions("did:a") == 1
    assert store.erase_contributions("did:b") == 0  # already gone
    assert store.get_edge("did:a", "did:b") == pytest.approx((0.0, 0.0))


# ---------------------------------------------------------------------------
# Surgical erasure on a shared edge (only the subject's deltas)
# ---------------------------------------------------------------------------


def test_erase_leaves_other_partys_revocable_on_same_edge() -> None:
    """On one edge, erasing B's valence-about-A must leave A's valence-about-B."""
    store = TopologyStore()
    store.update_valence(
        "did:a", "did:b", 1.0, 0.4, at=1.0, event_hash="ab", subject_did="did:b", revocable=True
    )
    store.update_valence(
        "did:b", "did:a", 1.0, 0.7, at=2.0, event_hash="ba", subject_did="did:a", revocable=True
    )
    store.erase_contributions("did:b")  # removes the a->b valence (about B)
    assert store.get_edge("did:a", "did:b") == pytest.approx((0.0, 0.0))
    assert store.get_edge("did:b", "did:a") == pytest.approx((0.0, 0.7))  # A's stays


# ---------------------------------------------------------------------------
# Ledger ↔ accumulator consistency + v0 back-compat boundary
# ---------------------------------------------------------------------------


def test_erasure_exact_under_float_residual() -> None:
    """Float-residual guard (verify-fanout regression): subtracting non-power-of-two
    contributions that fully cancel snaps the cell to empty. Without the snap,
    0.1+0.2+0.3 minus the same ≈ 8e-17 left a cell whose magnitude Σw·v/Σw ≈ 0.083 —
    a relationship value visible to consumers AFTER full Art. 17 erasure."""
    store = TopologyStore()
    for i, x in enumerate((0.1, 0.2, 0.3)):
        store.update_valence(
            "did:a", "did:b", x, x, at=float(i), event_hash=f"e{i}", subject_did="did:b"
        )
    assert store.erase_contributions("did:b") == 3
    fam, val = store.get_edge("did:a", "did:b")  # type: ignore[misc]
    assert val == 0.0  # exact zero after full erasure, not an amplified ~0.083 residual
    # the cell is dropped, not left as a machine-epsilon stale moment
    pair = store.get_pair("did:a", "did:b")
    assert pair is not None
    assert pair.served_moment("valence", "did:a", "did:b").sw == 0.0


def test_valence_subject_must_be_target() -> None:
    """A directional valence's sole data subject is its target; subject_did=from_did
    (the opinion-holder) is rejected — closes the consent/erasure laundering hole the
    verify-fanout found."""
    store = TopologyStore()
    with pytest.raises(ValueError, match="valence target"):
        store.update_valence(
            "did:a", "did:b", 1.0, 0.5, at=1.0, event_hash="e", subject_did="did:a"
        )
    # the target itself is accepted (the legitimate, redundant form)
    store.update_valence("did:a", "did:b", 1.0, 0.5, at=1.0, event_hash="e2", subject_did="did:b")
    assert store.get_edge("did:a", "did:b")[1] == pytest.approx(0.5)  # type: ignore[index]


def test_v0_no_hash_path_is_not_ledgered_so_not_contribution_erasable() -> None:
    """Back-compat boundary: an update with no event_hash updates the accumulator
    but writes no ledger entry, so erase_contributions can't remove it. The
    posture-3 bucket-zero fallback still covers such an edge."""
    store = TopologyStore()
    store.update_valence("did:a", "did:b", 1.0, 0.5, at=1.0)  # no event_hash
    store.erase_contributions("did:b")  # nothing to subtract
    assert store.get_edge("did:a", "did:b") == pytest.approx((0.0, 0.5))  # retained
    store.zero_revocable_bucket("did:a", "did:b")
    assert store.get_edge("did:a", "did:b") == pytest.approx((0.0, 0.0))
