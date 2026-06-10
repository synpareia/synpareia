"""Topology query algorithms — shortest path + path-aggregate computations."""

from __future__ import annotations

import math
from collections import deque
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from synpareia.topology.store import TopologyStore

_AGGREGATES = ("min", "product", "harmonic")


def shortest_path(
    store: TopologyStore,
    from_did: str,
    to_did: str,
    max_hops: int = 6,
    *,
    min_familiarity: float = 0.0,
) -> list[str] | None:
    """Return the shortest path between two DIDs as a list of DIDs, or None.

    Unweighted BFS over the edge graph. Only edges whose familiarity is strictly
    greater than ``min_familiarity`` count. ``max_hops`` bounds search depth.

    Returns ``[from_did]`` if ``from_did == to_did``; ``None`` if no path within bound.
    """
    if from_did == to_did:
        return [from_did]
    if max_hops < 1:
        return None

    visited: set[str] = {from_did}
    queue: deque[tuple[str, list[str]]] = deque([(from_did, [from_did])])

    while queue:
        current, path = queue.popleft()
        if len(path) - 1 >= max_hops:
            continue
        for neighbour in store.neighbours(current, min_familiarity=min_familiarity):
            if neighbour == to_did:
                return [*path, neighbour]
            if neighbour not in visited:
                visited.add(neighbour)
                queue.append((neighbour, [*path, neighbour]))

    return None


def path_strength(weights: list[float], aggregate: str = "min") -> float:
    """Aggregate a path's per-hop weights into a single scalar (pure helper).

    ``aggregate`` is one of:

    - ``"min"`` — the weakest link (v0 default; "a path is only as strong as its
      weakest hop").
    - ``"product"`` — multiplicative attenuation (each hop discounts the next);
      natural for normalised ``[0, 1]`` weights.
    - ``"harmonic"`` — harmonic mean; penalises any single weak hop hard.

    Returns ``0.0`` for an empty list or if **any** hop weight is ``<= 0`` — a
    zero/broken hop means no usable path strength, regardless of aggregate (this
    is what keeps ``min`` and the others consistent). Raises ``ValueError`` on an
    unknown aggregate. Pure — shared by the in-memory and directory path ops so
    the aggregation semantics can't drift."""
    if not weights:
        return 0.0
    if any(w <= 0 for w in weights):
        return 0.0
    if aggregate == "min":
        return min(weights)
    if aggregate == "product":
        return math.prod(weights)
    if aggregate == "harmonic":
        return len(weights) / sum(1.0 / w for w in weights)
    raise ValueError(f"unknown aggregate: {aggregate!r} (expected one of {_AGGREGATES})")


def path_familiarity(store: TopologyStore, path: list[str]) -> float:
    """Aggregate familiarity along a path. v0: ``min`` of per-hop familiarities.

    Returns 0.0 if the path has fewer than 2 nodes or any hop is missing.
    The semantic is "a path is only as strong as its weakest link." Delegates the
    aggregation to :func:`path_strength` (``min``) so the rule has one home.
    """
    if len(path) < 2:
        return 0.0

    hops: list[float] = []
    for from_did, to_did in zip(path, path[1:], strict=False):
        edge = store.get_edge(from_did, to_did)
        if edge is None:
            return 0.0
        familiarity, _valence = edge
        hops.append(familiarity)

    return path_strength(hops, "min")
