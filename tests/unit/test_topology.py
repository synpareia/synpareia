"""Tests for the v0 topology layer.

Demonstrates the load-bearing claim of the topology spec: agents can find each
other via the network even when they don't share a direct edge.
"""

from __future__ import annotations

import pytest

from synpareia.topology import (
    INTERACTION_CHANNEL,
    VALENCE_CHANNEL,
    EdgePair,
    TopologyStore,
    ordered_pair_key,
    path_familiarity,
    path_strength,
    shortest_path,
)

ALICE = "did:synpareia:alice"
BOB = "did:synpareia:bob"
CAROL = "did:synpareia:carol"
DAVE = "did:synpareia:dave"


class TestOrderedPairKey:
    def test_lex_order_preserved(self) -> None:
        assert ordered_pair_key(ALICE, BOB) == (ALICE, BOB)
        assert ordered_pair_key(BOB, ALICE) == (ALICE, BOB)

    def test_self_pair_rejected(self) -> None:
        with pytest.raises(ValueError, match="self-edges"):
            ordered_pair_key(ALICE, ALICE)


class TestEdgePair:
    def test_directional_view_returns_per_direction_values(self) -> None:
        pair = (
            EdgePair.new(ALICE, BOB)
            .with_channel_event(INTERACTION_CHANNEL, ALICE, BOB, 2.0, 0.0, at=100.0)
            .with_channel_event(VALENCE_CHANNEL, ALICE, BOB, 1.0, 0.5, at=100.0)
            .with_channel_event(VALENCE_CHANNEL, BOB, ALICE, 1.0, -0.3, at=100.0)
        )
        # familiarity (interaction backing) is symmetric; valence is directional.
        assert pair.directional_view(ALICE, BOB) == (2.0, 0.5)
        assert pair.directional_view(BOB, ALICE) == (2.0, -0.3)

    def test_interaction_update_increments_both_directions(self) -> None:
        pair = EdgePair.new(ALICE, BOB).with_channel_event(
            INTERACTION_CHANNEL, ALICE, BOB, 1.0, 0.0, at=50.0
        )
        assert pair.served_familiarity(ALICE, BOB) == 1.0
        assert pair.served_familiarity(BOB, ALICE) == 1.0  # symmetric
        assert pair.last_event_at == 50.0

    def test_valence_update_is_directional(self) -> None:
        pair = EdgePair.new(ALICE, BOB).with_channel_event(
            VALENCE_CHANNEL, ALICE, BOB, 1.0, 0.5, at=50.0
        )
        assert pair.served_valence(ALICE, BOB) == 0.5
        assert pair.served_valence(BOB, ALICE) == 0.0  # directional; reverse empty
        # Reverse direction:
        updated2 = pair.with_channel_event(VALENCE_CHANNEL, BOB, ALICE, 1.0, -0.3, at=60.0)
        assert updated2.served_valence(ALICE, BOB) == 0.5
        assert updated2.served_valence(BOB, ALICE) == -0.3
        assert updated2.last_event_at == 60.0


class TestTopologyStoreUpdates:
    def test_no_edge_initially(self) -> None:
        store = TopologyStore()
        assert store.get_edge(ALICE, BOB) is None

    def test_record_co_interaction_creates_edge(self) -> None:
        store = TopologyStore()
        store.record_co_interaction(ALICE, BOB, weight=1.0, at=100.0)
        edge = store.get_edge(ALICE, BOB)
        assert edge is not None
        familiarity, valence = edge
        assert familiarity == 1.0
        assert valence == 0.0
        # And both directions show familiarity:
        rev_edge = store.get_edge(BOB, ALICE)
        assert rev_edge is not None
        rev_familiarity, _ = rev_edge
        assert rev_familiarity == 1.0

    def test_repeated_co_interaction_accumulates(self) -> None:
        store = TopologyStore()
        store.record_co_interaction(ALICE, BOB, weight=1.0, at=100.0)
        store.record_co_interaction(ALICE, BOB, weight=0.5, at=200.0)
        edge = store.get_edge(ALICE, BOB)
        assert edge is not None
        familiarity, _ = edge
        assert familiarity == 1.5

    def test_valence_is_directional(self) -> None:
        store = TopologyStore()
        store.update_valence(ALICE, BOB, 1.0, 0.5, at=100.0)
        store.update_valence(BOB, ALICE, 1.0, -0.3, at=100.0)
        fwd = store.get_edge(ALICE, BOB)
        rev = store.get_edge(BOB, ALICE)
        assert fwd is not None
        assert rev is not None
        _, v_a_to_b = fwd
        _, v_b_to_a = rev
        assert v_a_to_b == 0.5
        assert v_b_to_a == -0.3

    def test_valence_update_creates_edge_with_zero_familiarity(self) -> None:
        store = TopologyStore()
        store.update_valence(ALICE, BOB, 1.0, 0.5, at=100.0)
        edge = store.get_edge(ALICE, BOB)
        assert edge is not None
        familiarity, valence = edge
        assert familiarity == 0.0
        assert valence == 0.5

    def test_co_interaction_with_self_raises(self) -> None:
        store = TopologyStore()
        with pytest.raises(ValueError, match="distinct DIDs"):
            store.record_co_interaction(ALICE, ALICE, at=100.0)

    def test_valence_to_self_raises(self) -> None:
        store = TopologyStore()
        with pytest.raises(ValueError, match="self-valence"):
            store.update_valence(ALICE, ALICE, 1.0, 0.5, at=100.0)

    def test_negative_co_interaction_weight_rejected(self) -> None:
        store = TopologyStore()
        with pytest.raises(ValueError, match="non-negative"):
            store.record_co_interaction(ALICE, BOB, weight=-1.0, at=100.0)

    def test_infinite_co_interaction_weight_rejected(self) -> None:
        store = TopologyStore()
        with pytest.raises(ValueError, match="finite"):
            store.record_co_interaction(ALICE, BOB, weight=float("inf"), at=100.0)

    def test_zero_co_interaction_weight_allowed(self) -> None:
        """Zero is non-negative and finite; permitted (no-op on familiarity)."""
        store = TopologyStore()
        store.record_co_interaction(ALICE, BOB, weight=0.0, at=100.0)
        edge = store.get_edge(ALICE, BOB)
        assert edge is not None
        familiarity, _ = edge
        assert familiarity == 0.0

    def test_adjacency_index_consistent_after_updates(self) -> None:
        """The adjacency index is the load-bearing perf optimisation; verify correctness."""
        store = TopologyStore()
        store.record_co_interaction(ALICE, BOB, weight=1.0, at=100.0)
        store.update_valence(ALICE, CAROL, 1.0, 0.3, at=100.0)
        store.record_co_interaction(BOB, CAROL, weight=2.0, at=100.0)

        # Alice neighbours via index should match a full-scan reference:
        alice_neighbours_via_index = {v.counterpart_did for v in store.edges_for(ALICE)}
        assert alice_neighbours_via_index == {BOB, CAROL}

        bob_neighbours = {v.counterpart_did for v in store.edges_for(BOB)}
        assert bob_neighbours == {ALICE, CAROL}

        carol_neighbours = {v.counterpart_did for v in store.edges_for(CAROL)}
        assert carol_neighbours == {ALICE, BOB}


class TestTopologyStoreReads:
    def test_edges_for_returns_outgoing_views(self) -> None:
        store = TopologyStore()
        store.record_co_interaction(ALICE, BOB, weight=1.0, at=100.0)
        store.record_co_interaction(ALICE, CAROL, weight=2.0, at=100.0)
        views = sorted(store.edges_for(ALICE), key=lambda v: v.counterpart_did)
        assert len(views) == 2
        assert views[0].counterpart_did == BOB
        assert views[0].familiarity == 1.0
        assert views[1].counterpart_did == CAROL
        assert views[1].familiarity == 2.0

    def test_edges_for_isolated_did_is_empty(self) -> None:
        store = TopologyStore()
        store.record_co_interaction(BOB, CAROL, weight=1.0, at=100.0)
        assert store.edges_for(ALICE) == []

    def test_neighbours_respects_familiarity_threshold(self) -> None:
        store = TopologyStore()
        store.record_co_interaction(ALICE, BOB, weight=1.0, at=100.0)
        store.update_valence(ALICE, CAROL, 1.0, 0.5, at=100.0)  # zero familiarity
        assert store.neighbours(ALICE, min_familiarity=0.0) == [BOB]
        assert store.neighbours(ALICE, min_familiarity=0.5) == [BOB]
        assert store.neighbours(ALICE, min_familiarity=1.5) == []


class TestShortestPath:
    """Demonstrates the load-bearing v0 claim: non-adjacent nodes connect via the graph."""

    def test_same_node_returns_singleton(self) -> None:
        store = TopologyStore()
        assert shortest_path(store, ALICE, ALICE) == [ALICE]

    def test_direct_edge_returns_two_node_path(self) -> None:
        store = TopologyStore()
        store.record_co_interaction(ALICE, BOB, weight=1.0, at=100.0)
        assert shortest_path(store, ALICE, BOB) == [ALICE, BOB]

    def test_one_hop_intermediate(self) -> None:
        """The load-bearing demonstration: A and C don't share an edge, but B connects them."""
        store = TopologyStore()
        store.record_co_interaction(ALICE, BOB, weight=1.0, at=100.0)
        store.record_co_interaction(BOB, CAROL, weight=1.0, at=100.0)
        # A and C have no direct edge:
        assert store.get_edge(ALICE, CAROL) is None
        # But the network connects them:
        path = shortest_path(store, ALICE, CAROL)
        assert path == [ALICE, BOB, CAROL]

    def test_two_hop_intermediate(self) -> None:
        """A — B — C — D chain. A finds D via two hops."""
        store = TopologyStore()
        store.record_co_interaction(ALICE, BOB, weight=1.0, at=100.0)
        store.record_co_interaction(BOB, CAROL, weight=1.0, at=100.0)
        store.record_co_interaction(CAROL, DAVE, weight=1.0, at=100.0)
        path = shortest_path(store, ALICE, DAVE)
        assert path == [ALICE, BOB, CAROL, DAVE]

    def test_max_hops_caps_search(self) -> None:
        """A — B — C — D, with max_hops=2, should not find D."""
        store = TopologyStore()
        store.record_co_interaction(ALICE, BOB, weight=1.0, at=100.0)
        store.record_co_interaction(BOB, CAROL, weight=1.0, at=100.0)
        store.record_co_interaction(CAROL, DAVE, weight=1.0, at=100.0)
        assert shortest_path(store, ALICE, DAVE, max_hops=2) is None
        assert shortest_path(store, ALICE, CAROL, max_hops=2) == [ALICE, BOB, CAROL]

    def test_no_path_returns_none(self) -> None:
        """A — B, separate component C — D. No path A to D."""
        store = TopologyStore()
        store.record_co_interaction(ALICE, BOB, weight=1.0, at=100.0)
        store.record_co_interaction(CAROL, DAVE, weight=1.0, at=100.0)
        assert shortest_path(store, ALICE, DAVE) is None

    def test_min_familiarity_filter_excludes_weak_edges(self) -> None:
        """Weak edges below threshold don't count for path-finding."""
        store = TopologyStore()
        store.record_co_interaction(ALICE, BOB, weight=0.2, at=100.0)
        store.record_co_interaction(BOB, CAROL, weight=1.0, at=100.0)
        # With high min_familiarity, the A-B weak edge is excluded:
        assert shortest_path(store, ALICE, CAROL, min_familiarity=0.5) is None
        # Default threshold (0.0) finds the path:
        assert shortest_path(store, ALICE, CAROL) == [ALICE, BOB, CAROL]


class TestPathFamiliarity:
    def test_empty_path_returns_zero(self) -> None:
        store = TopologyStore()
        assert path_familiarity(store, []) == 0.0
        assert path_familiarity(store, [ALICE]) == 0.0

    def test_path_familiarity_is_min_of_hops(self) -> None:
        """A path is only as strong as its weakest link."""
        store = TopologyStore()
        store.record_co_interaction(ALICE, BOB, weight=2.0, at=100.0)
        store.record_co_interaction(BOB, CAROL, weight=0.5, at=100.0)
        # Both hops have familiarity; the weaker hop (0.5) determines path strength:
        assert path_familiarity(store, [ALICE, BOB, CAROL]) == 0.5

    def test_missing_hop_returns_zero(self) -> None:
        store = TopologyStore()
        store.record_co_interaction(ALICE, BOB, weight=2.0, at=100.0)
        # No B-C edge:
        assert path_familiarity(store, [ALICE, BOB, CAROL]) == 0.0


class TestPathStrength:
    """The pure aggregator shared by the in-memory and directory path ops."""

    def test_min_is_weakest_link(self) -> None:
        assert path_strength([0.5, 2.0, 1.0], "min") == 0.5

    def test_default_aggregate_is_min(self) -> None:
        assert path_strength([0.5, 2.0]) == 0.5

    def test_product_attenuates(self) -> None:
        assert path_strength([0.5, 0.4], "product") == pytest.approx(0.2)

    def test_harmonic_mean(self) -> None:
        # harmonic mean of [1, 1] is 1; of [1, 0.5] is 2/(1 + 2) = 0.6667
        assert path_strength([1.0, 1.0], "harmonic") == pytest.approx(1.0)
        assert path_strength([1.0, 0.5], "harmonic") == pytest.approx(2 / 3)

    def test_empty_is_zero(self) -> None:
        assert path_strength([], "min") == 0.0

    def test_any_nonpositive_hop_is_zero_for_all_aggregates(self) -> None:
        for agg in ("min", "product", "harmonic"):
            assert path_strength([1.0, 0.0, 2.0], agg) == 0.0
            assert path_strength([1.0, -0.5], agg) == 0.0

    def test_unknown_aggregate_raises(self) -> None:
        with pytest.raises(ValueError, match="unknown aggregate"):
            path_strength([1.0], "median")

    def test_path_familiarity_delegates_to_min(self) -> None:
        store = TopologyStore()
        store.record_co_interaction(ALICE, BOB, weight=2.0, at=100.0)
        store.record_co_interaction(BOB, CAROL, weight=0.5, at=100.0)
        assert path_familiarity(store, [ALICE, BOB, CAROL]) == path_strength([2.0, 0.5], "min")


class TestEndToEndScenario:
    """The dead-simple integration test the user asked for:

    "Operate between two nodes that don't share an edge but are connected indirectly."
    """

    def test_alice_finds_carol_through_bob(self) -> None:
        # Substrate state: Alice and Bob interacted; Bob and Carol interacted.
        # Alice has never directly interacted with Carol.
        store = TopologyStore()
        store.record_co_interaction(ALICE, BOB, weight=1.0, at=100.0)
        store.record_co_interaction(BOB, CAROL, weight=1.0, at=200.0)

        # Alice queries the network: is Carol reachable?
        path = shortest_path(store, ALICE, CAROL)
        assert path is not None, "Alice should find Carol via Bob"
        assert path == [ALICE, BOB, CAROL]

        # What's the path's aggregate familiarity?
        strength = path_familiarity(store, path)
        assert strength == 1.0  # min of two equal-strength hops

        # Alice's neighbourhood doesn't include Carol directly:
        alice_neighbours = store.neighbours(ALICE)
        assert BOB in alice_neighbours
        assert CAROL not in alice_neighbours

        # But the network knows Carol exists in Alice's reachable graph:
        assert CAROL in store.all_dids()
