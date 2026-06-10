"""Unit tests for the read-time anchored transitive aggregate (`topology.aggregate`).

Pins the Slice-3 exit criteria: transitive author-weights are anchored (two askers
differ; α=1 degenerates to one-hop; an unconnected asker is immune to a sybil
cluster; each extra hop discounts by (1-α)); `combine` is exact precision-fusion;
the aggregate over a seeded graph blends trusted opinions with the asker's private
view; and the output is a bare (magnitude, confidence) — no author/path identity.
"""

from __future__ import annotations

import math

import pytest

from synpareia.topology import (
    VISIBILITY_NETWORK_TRAVERSABLE,
    SummaryStat,
    TopologyStore,
    aggregate_reputation,
    combine,
    summary_statistic,
    transitive_author_weights,
)

A = "did:key:zA"
B = "did:key:zB"
C = "did:key:zC"
D = "did:key:zD"
X = "did:key:zX"


def _fam(store: TopologyStore, a: str, b: str, weight: float = 1.0) -> None:
    store.record_co_interaction(a, b, weight=weight)


def _net_valence(store: TopologyStore, frm: str, to: str, v: float, **kw: object) -> None:
    """Record a valence the author has made network-traversable (may-deliver) — so it
    can feed a third-party asker's aggregate. (Default visibility is bilateral, which a
    third-party read excludes; most aggregate tests want the opinion to be visible.)"""
    store.update_valence(
        frm, to, kw.pop("w", 1.0), v, visibility=VISIBILITY_NETWORK_TRAVERSABLE, **kw
    )  # type: ignore[arg-type]


# --- combine + summary_statistic ------------------------------------------


def test_combine_precision_weighted() -> None:
    # equal confidence → simple mean
    r = combine(SummaryStat(0.8, 1.0), SummaryStat(0.2, 1.0))
    assert r.magnitude == pytest.approx(0.5)
    assert r.confidence == pytest.approx(2.0)


def test_combine_weights_by_confidence() -> None:
    # higher-confidence side pulls the mean toward it
    r = combine(SummaryStat(1.0, 3.0), SummaryStat(0.0, 1.0))
    assert r.magnitude == pytest.approx(0.75)  # (3*1 + 1*0)/4
    assert r.confidence == pytest.approx(4.0)


def test_combine_zero_backing_is_empty() -> None:
    r = combine(SummaryStat(0.0, 0.0), SummaryStat(0.0, 0.0))
    assert r == SummaryStat(0.0, 0.0)


def test_combine_with_empty_side_passes_other_through() -> None:
    r = combine(SummaryStat(0.6, 2.0), SummaryStat(0.0, 0.0))
    assert r.magnitude == pytest.approx(0.6)
    assert r.confidence == pytest.approx(2.0)


def test_summary_statistic_clamp() -> None:
    assert summary_statistic(1.6, 3.0, clamp_to_unit=True) == SummaryStat(1.0, 3.0)
    assert summary_statistic(1.6, 3.0).magnitude == pytest.approx(1.6)  # unclamped


# --- transitive_author_weights --------------------------------------------


def test_direct_neighbour_undiscounted_two_hop_discounted() -> None:
    # A—B—C, all familiarity=1 → nf = 1/(1+1) = 0.5 per hop
    _fam(store := TopologyStore(), A, B)
    _fam(store, B, C)
    w = transitive_author_weights(store, A, alpha=0.5, max_hops=3)
    assert w[B] == pytest.approx(0.5)  # direct: nf only
    assert w[C] == pytest.approx(0.5 * 0.5 * 0.5)  # nf·nf·(1-α)


@pytest.mark.parametrize("bad_alpha", [-0.1, 1.1, 2.0, -1.0])
def test_alpha_out_of_unit_range_rejected(bad_alpha: float) -> None:
    """α∉[0,1] is a hard correctness invariant: α<0 would amplify weight with distance
    (inverting the sybil guarantee), α>1 would make hop factors negative."""
    _fam(store := TopologyStore(), A, B)
    with pytest.raises(ValueError, match="alpha must be in"):
        transitive_author_weights(store, A, alpha=bad_alpha)
    # and through the full aggregate path
    with pytest.raises(ValueError, match="alpha must be in"):
        aggregate_reputation(store, A, B, alpha=bad_alpha)


def test_alpha_one_degenerates_to_one_hop() -> None:
    _fam(store := TopologyStore(), A, B)
    _fam(store, B, C)
    w = transitive_author_weights(store, A, alpha=1.0, max_hops=3)
    assert B in w  # direct survives (undiscounted by α)
    assert C not in w  # (1-α)=0 zeroes every transitive hop


def test_two_askers_get_different_weights() -> None:
    # A—B—C: A's trust in C is 2-hop; B's trust in C is 1-hop → different
    _fam(store := TopologyStore(), A, B)
    _fam(store, B, C)
    wa = transitive_author_weights(store, A, alpha=0.5, max_hops=3)
    wb = transitive_author_weights(store, B, alpha=0.5, max_hops=3)
    assert wb[C] > wa[C]  # B is closer to C than A is → personalised


def test_unconnected_asker_sees_nothing() -> None:
    _fam(store := TopologyStore(), B, C)  # a cluster A is not part of
    w = transitive_author_weights(store, A, alpha=0.5, max_hops=3)
    assert w == {}  # A reaches nobody


def test_best_path_wins_when_two_paths_exist() -> None:
    # A reaches C directly AND via B; the direct (1-hop, undiscounted) path wins
    _fam(store := TopologyStore(), A, B)
    _fam(store, B, C)
    _fam(store, A, C)
    w = transitive_author_weights(store, A, alpha=0.5, max_hops=3)
    assert w[C] == pytest.approx(0.5)  # direct nf, not the discounted 2-hop value


def test_max_hops_bounds_reach() -> None:
    _fam(store := TopologyStore(), A, B)
    _fam(store, B, C)
    _fam(store, C, D)
    w = transitive_author_weights(store, A, alpha=0.5, max_hops=2)
    assert C in w  # 2 hops, within bound
    assert D not in w  # 3 hops, beyond max_hops=2


# --- aggregate_reputation -------------------------------------------------


def test_aggregate_reflects_trusted_opinion() -> None:
    # A trusts B (direct); B holds valence 0.8 about X (network-traversable); A has no
    # private opinion.
    _fam(store := TopologyStore(), A, B)
    _net_valence(store, B, X, 0.8)
    r = aggregate_reputation(store, A, X, alpha=0.5, max_hops=3)
    assert r.magnitude == pytest.approx(0.8)  # network speaks; private empty
    assert r.confidence == pytest.approx(0.5 * 1.0)  # w(A,B)·c_B


def test_aggregate_blends_private_with_network() -> None:
    _fam(store := TopologyStore(), A, B)
    _net_valence(store, B, X, 1.0)  # B loves X (network-traversable)
    store.update_valence(A, X, w=1.0, v=0.0)  # A is neutral on X (private; visible to A)
    r = aggregate_reputation(store, A, X, alpha=0.5, max_hops=3)
    # network: m=1.0 c=0.5 ; private: m=0.0 c=1.0 → (0.5*1 + 1*0)/1.5
    assert r.magnitude == pytest.approx((0.5 * 1.0 + 1.0 * 0.0) / 1.5)
    assert r.confidence == pytest.approx(1.5)


def test_unconnected_asker_immune_to_sybil_cluster() -> None:
    # A sybil cluster B,C all vouch X strongly, but asker D can't reach them.
    _fam(store := TopologyStore(), B, C)
    _net_valence(store, B, X, 1.0, w=10.0)
    _net_valence(store, C, X, 1.0, w=10.0)
    r = aggregate_reputation(store, D, X, alpha=0.5, max_hops=3)
    assert r == SummaryStat(0.0, 0.0)  # D reaches nobody → no influence


def test_distance_discounts_a_distant_opinion() -> None:
    # A directly trusts B (B dislikes X); a more-distant agent S (2 hops via M) likes
    # X with *equal* backing. The α-discount on distance keeps the closer, directly-
    # trusted opinion on top. (Note: v1 does NOT defend against *inflated* backing —
    # fake-backing sybil resistance is deferred to Slice 4 rate-limits/stake-gating;
    # here both backings are equal so the test isolates the distance-discount.)
    _fam(store := TopologyStore(), A, B)
    _fam(store, A, "M")
    _fam(store, "M", "S")
    _net_valence(store, B, X, -0.8)  # trusted neighbour: negative
    _net_valence(store, "S", X, 1.0)  # distant agent, equal backing: positive
    r = aggregate_reputation(store, A, X, alpha=0.5, max_hops=3)
    assert r.magnitude < 0  # the closer, directly-trusted negative opinion wins


def test_output_carries_no_author_or_path() -> None:
    _fam(store := TopologyStore(), A, B)
    _net_valence(store, B, X, 0.5)
    r = aggregate_reputation(store, A, X)
    # the served shape is exactly two floats — no DIDs, no path, no author list
    assert set(vars(r).keys()) == {"magnitude", "confidence"}
    assert all(isinstance(getattr(r, k), float) for k in ("magnitude", "confidence"))


def test_erasure_recomputes_aggregate() -> None:
    # erasure-by-recompute: the aggregate is read-time, so erasing the opinions about
    # X changes it on the next read. A valence event "B about X" is data about X (the
    # target is the subject), so it's X's Art-17 erasure that removes it.
    _fam(store := TopologyStore(), A, B)
    _net_valence(store, B, X, 0.8, event_hash="ev")
    before = aggregate_reputation(store, A, X)
    store.erase_contributions(X)  # X exercises Art. 17 over opinions about X
    after = aggregate_reputation(store, A, X)
    assert before.magnitude == pytest.approx(0.8)
    assert after == SummaryStat(0.0, 0.0)  # nothing left to say about X


def test_magnitude_stays_in_unit_range() -> None:
    _fam(store := TopologyStore(), A, B)
    _fam(store, A, C)
    _net_valence(store, B, X, 2.0)  # raw out-of-range value
    _net_valence(store, C, X, -2.0)
    r = aggregate_reputation(store, A, X)
    assert -1.0 <= r.magnitude <= 1.0
    assert math.isfinite(r.confidence)


# --- minimum-visibility (§11.3 BI-3/BI-5) ---------------------------------


def test_bilateral_opinion_excluded_from_third_party_aggregate() -> None:
    """An author's bilateral (not may-deliver) opinion never reaches a third-party
    asker's aggregate — the load-bearing min-visibility control."""
    _fam(store := TopologyStore(), A, B)
    store.update_valence(B, X, w=1.0, v=0.9)  # default visibility = bilateral
    r = aggregate_reputation(store, A, X)
    assert r == SummaryStat(0.0, 0.0)  # B's bilateral opinion is invisible to A


def test_network_traversable_opinion_included() -> None:
    _fam(store := TopologyStore(), A, B)
    _net_valence(store, B, X, 0.9)  # may-deliver → network_traversable
    r = aggregate_reputation(store, A, X)
    assert r.magnitude == pytest.approx(0.9)


def test_private_edge_visible_to_asker_regardless_of_class() -> None:
    """The asker's OWN edge is visible to them at any visibility class (they are a
    party) — a bilateral private opinion still feeds the asker's own aggregate."""
    store = TopologyStore()
    store.update_valence(A, X, w=1.0, v=0.7)  # A's own, bilateral
    r = aggregate_reputation(store, A, X)
    assert r.magnitude == pytest.approx(0.7)  # private side reads all visibility


def test_mixed_visibility_only_traversable_portion_counts() -> None:
    """An edge with both a bilateral and a network_traversable valence event: a
    third-party read sees only the network_traversable portion."""
    _fam(store := TopologyStore(), A, B)
    _net_valence(store, B, X, 1.0, w=2.0, event_hash="net")  # traversable, backing 2
    store.update_valence(B, X, w=8.0, v=-1.0, event_hash="bi")  # bilateral, backing 8
    r = aggregate_reputation(store, A, X)
    # only the +1.0 (backing 2) is visible; the -1.0 bilateral is excluded
    assert r.magnitude == pytest.approx(1.0)
    assert r.confidence == pytest.approx(0.5 * 2.0)  # w(A,B)=0.5 · visible backing 2


def test_bilateral_opinion_still_erasable_and_invisible() -> None:
    """A bilateral opinion is recorded (may-tune) but invisible to third parties;
    erasure still works on it (visibility ⊥ revocability)."""
    _fam(store := TopologyStore(), A, B)
    store.update_valence(B, X, w=1.0, v=0.9, event_hash="bi")  # bilateral, revocable
    # invisible to A regardless
    assert aggregate_reputation(store, A, X) == SummaryStat(0.0, 0.0)
    # but X can still erase it (raw served read sees it; erasure subtracts the cell)
    assert store.get_served_edge(B, X)[1] == pytest.approx(
        0.9
    )  # raw read sees all  # type: ignore[index]
    store.erase_contributions(X)
    assert store.get_served_edge(B, X) is None or store.get_served_edge(B, X)[1] == pytest.approx(
        0.0
    )


def test_erase_clears_both_visibility_classes() -> None:
    """A subject's revocable valence spread across BOTH visibility classes on one
    edge is fully cleared by erasure — no residue in either cell (GDPR Art-17 ×
    §11.3). Regression for the verify-fanout coverage gap: a regression that erased
    against DEFAULT_VISIBILITY instead of the contribution's own class would leave
    network_traversable residue visible to third parties."""
    from synpareia.topology import VALENCE_CHANNEL, VISIBILITY_BILATERAL
    from synpareia.topology import VISIBILITY_NETWORK_TRAVERSABLE as NET

    store = TopologyStore()
    store.update_valence(B, X, 2.0, 1.0, event_hash="net", visibility=NET)
    store.update_valence(B, X, 8.0, -1.0, event_hash="bi", visibility=VISIBILITY_BILATERAL)
    pair = store.get_pair(B, X)
    assert pair is not None
    # both cells present: the network portion is backing 2, the full edge backing 10
    assert pair.served_moment_visible(VALENCE_CHANNEL, B, X, frozenset({NET})).sw == pytest.approx(
        2.0
    )
    assert pair.served_moment(VALENCE_CHANNEL, B, X).sw == pytest.approx(10.0)
    # X erases → both visibility cells cleared, no residue in either
    store.erase_contributions(X)
    after = store.get_pair(B, X)
    if after is not None:
        assert after.served_moment(VALENCE_CHANNEL, B, X).sw == pytest.approx(0.0)
        assert after.served_moment_visible(
            VALENCE_CHANNEL, B, X, frozenset({NET})
        ).sw == pytest.approx(0.0)
