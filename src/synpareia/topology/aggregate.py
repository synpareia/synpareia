"""Read-time anchored transitive reputation aggregate (build-phase Slice 3).

The read-time keystone (``topology-idealized-model.md`` §L3, ``topology-function-
contracts.md`` §4a): given an **asker** ``A`` and a **subject** ``X``, compute a
personalised, asker-anchored, transitive summary of X's reputation — other agents'
opinions about X, each weighted by A's bounded-hop path-discounted *trust* in that
agent and by that agent's own backing, then combined with A's own *private* opinion
of X.

Everything here is **read-time + pure**: no write-time cross-pair propagation,
nothing materialised (the keystone — ``contracts`` §4a). The output is **collapsed**:
a ``(magnitude, confidence)`` :class:`SummaryStat` with *no author or path identity*
(legal §11.4 inv. 3, advisory-to-asker).

The anchor floor ``α`` (decision #2, ``α ≥ 0.5``) is the single knob carrying all
three guarantees:

- **personalised** — weights are computed from A's own edges, so two askers get
  different answers (not a global score);
- **legal (§Q6)** — read-time + asker-anchored, never a stored global per-agent
  score (which would be counsel-gated);
- **sybil-resistant** — α enters as a per-hop discount ``(1-α)^(hops-1)``, so a
  cluster an asker can only reach at ≥2 hops is capped at ``(1-α)^(d-1)``; at
  ``α = 1`` the transitive term vanishes entirely (degenerates to one-hop).

Recursion-resolution strategy = **bounded-hop path-discount** for v1 (decision #1);
full personalised-PageRank iteration (idealized §L3) is the documented next step.
Decay is deferred (decision #3): the read-time shape leaves a per-edge hook but
nothing is materialised here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from synpareia.topology.model import THIRD_PARTY_VISIBLE, VALENCE_CHANNEL
from synpareia.topology.readtime import clamp_valence

if TYPE_CHECKING:
    from synpareia.topology.model import EdgePair


class TopologyReader(Protocol):
    """The minimal read interface the aggregate needs — satisfied structurally by
    the SDK :class:`~synpareia.topology.store.TopologyStore` and by the directory's
    bounded-subgraph snapshot. Keeping the aggregate to this surface lets the same
    pure logic run over in-memory and directory-backed graphs without drift."""

    def get_pair(self, did_a: str, did_b: str) -> EdgePair | None: ...

    def neighbours(self, did: str, *, min_familiarity: float = ...) -> list[str]: ...


#: v1 anchor floor (decision #2). Each hop beyond the asker's direct neighbours
#: discounts the transitive weight by ``(1-α)``. ``α ≥ 0.5`` → strong anchoring on
#: a sparse young graph; ``α = 1`` → one-hop only. Dojo-tunable.
DEFAULT_ALPHA = 0.5

#: v1 bounded-hop horizon for the transitive walk.
DEFAULT_MAX_HOPS = 3

#: Saturation constant mapping an unbounded served familiarity ``Σw`` to a per-hop
#: trust in ``[0, 1)`` via ``fam / (fam + SAT)`` — so a path-product discounts with
#: each hop and no single strong edge can dominate without bound.
FAMILIARITY_SATURATION = 1.0

_EPS = 1e-9


@dataclass(frozen=True)
class SummaryStat:
    """A served summary statistic — the two-value shape (``contracts`` §4): a
    ``magnitude`` (the agent-meaningful quantity) plus a ``confidence`` (its
    backing). **Collapsed**: carries no author or path identity. ``confidence`` is
    the backing weight ``Σw`` in v1 (the cheap additive option; a variance-based
    confidence is a later additive upgrade, ``contracts`` §2a)."""

    magnitude: float
    confidence: float


def summary_statistic(
    moment_magnitude: float, moment_confidence: float, *, clamp_to_unit: bool = False
) -> SummaryStat:
    """The two-stage boundary (``contracts`` §4): map a linear accumulator's
    ``(magnitude, confidence)`` read-offs to a served :class:`SummaryStat`.

    v1 ``magnitude`` is the backing-weighted mean ``Σw·v / Σw`` (optionally clamped
    to ``[-1, 1]`` for valence); ``confidence`` is the backing ``Σw``. Non-linear /
    ML magnitudes and variance confidence are additive extensions over the same
    stored sums.
    """
    mag = clamp_valence(moment_magnitude) if clamp_to_unit else moment_magnitude
    return SummaryStat(mag, moment_confidence)


def combine(a: SummaryStat, b: SummaryStat) -> SummaryStat:
    """Precision-weighted fusion of two summary statistics (``contracts`` §4):

        m = (c_a·m_a + c_b·m_b) / (c_a + c_b),   c = c_a + c_b

    **Exact** when both confidences are additive backing weights (``Σw`` — the v1
    case). A non-additive confidence (e.g. ML-derived) makes the sum an
    approximation; v1 only ever combines additive ``Σw`` so the fusion is exact.
    Zero total backing → an empty ``(0, 0)`` stat.
    """
    c = a.confidence + b.confidence
    if c <= _EPS:
        return SummaryStat(0.0, 0.0)
    m = (a.confidence * a.magnitude + b.confidence * b.magnitude) / c
    return SummaryStat(m, c)


def _normalized_familiarity(store: TopologyReader, u: str, v: str) -> float:
    """Map the ``u``–``v`` edge's unbounded served familiarity ``Σw`` to a per-hop
    trust in ``[0, 1)`` via saturation, so a path-product discounts with length."""
    pair = store.get_pair(u, v)
    if pair is None:
        return 0.0
    fam = pair.served_familiarity(u, v)
    if fam <= 0.0:
        return 0.0
    return fam / (fam + FAMILIARITY_SATURATION)


def transitive_author_weights(
    store: TopologyReader,
    asker: str,
    *,
    alpha: float = DEFAULT_ALPHA,
    max_hops: int = DEFAULT_MAX_HOPS,
) -> dict[str, float]:
    """The asker's bounded-hop, path-discounted *trust* in every reachable agent.

        w(A, Z) = (Π normalized per-hop familiarity along the best path) · (1-α)^(hops-1)

    Direct neighbours are undiscounted (the anchor); each additional hop multiplies
    by ``(1-α)``. The "best" path is the one maximising the final discounted weight,
    found by ``max_hops`` rounds of max-relaxation. Deterministic (sorted iteration).
    Excludes the asker; drops negligible weights. ``α = 1`` ⇒ only direct neighbours
    survive (the transitive term is zeroed).

    ``alpha`` must be in ``[0, 1]`` — a hard correctness invariant, not merely the
    ratified ``α ≥ 0.5`` tuning floor. ``α < 0`` would make ``(1-α) > 1``, *amplifying*
    weight with distance and inverting the sybil-by-distance guarantee; ``α > 1`` would
    make hop factors negative. (Values in ``[0, 0.5)`` are accepted for dojo sweeps but
    weaken anchoring below the ratified floor.)
    """
    if not (0.0 <= alpha <= 1.0):
        raise ValueError(f"alpha must be in [0, 1] (sybil-discount invariant); got {alpha!r}")
    # Max-weight relaxation with in-place updates within each round (not snapshot
    # Bellman-Ford). Correct here because weights are monotone non-decreasing (the
    # `cand > weight[v]` guard) and every factor is in (0, 1], so extra hops can never
    # exceed a found weight — the fixpoint is order-independent.
    weight: dict[str, float] = {asker: 1.0}
    hops: dict[str, int] = {asker: 0}
    for _ in range(max_hops):
        updated = False
        for u in sorted(weight):
            if hops[u] >= max_hops:
                continue
            hop_factor = (1.0 - alpha) if hops[u] >= 1 else 1.0
            base = weight[u]
            for v in sorted(store.neighbours(u)):
                if v == asker:
                    continue
                nf = _normalized_familiarity(store, u, v)
                if nf <= 0.0:
                    continue
                cand = base * nf * hop_factor
                if cand > weight.get(v, 0.0) + _EPS:
                    weight[v] = cand
                    hops[v] = hops[u] + 1
                    updated = True
        if not updated:
            break
    return {z: w for z, w in weight.items() if z != asker and w > _EPS}


def _valence_summary(
    store: TopologyReader,
    from_did: str,
    to_did: str,
    *,
    visibilities: frozenset[str] | None = None,
) -> SummaryStat:
    """Served valence ``(magnitude clamped to [-1,1], confidence = Σw backing)`` for
    a directed edge, or an empty stat when the edge is absent.

    ``visibilities`` is the minimum-visibility filter (§11.3 BI-3): a third-party
    read passes only the classes the asker may see (``THIRD_PARTY_VISIBLE``); the
    asker's own/private edge passes ``None`` — the asker is a party, so visibility
    doesn't gate it, and it sums all classes."""
    pair = store.get_pair(from_did, to_did)
    if pair is None:
        return SummaryStat(0.0, 0.0)
    moment = (
        pair.served_moment_visible(VALENCE_CHANNEL, from_did, to_did, visibilities)
        if visibilities is not None
        else pair.served_moment(VALENCE_CHANNEL, from_did, to_did)
    )
    return summary_statistic(moment.magnitude, moment.confidence, clamp_to_unit=True)


def aggregate_reputation(
    store: TopologyReader,
    asker: str,
    subject: str,
    *,
    alpha: float = DEFAULT_ALPHA,
    max_hops: int = DEFAULT_MAX_HOPS,
) -> SummaryStat:
    """The read-time anchored transitive valence reputation of ``subject`` as seen by
    ``asker``.

    The network estimate weights each *other* agent Z's valence about ``subject`` by
    ``w(A, Z)`` (the asker's trust in Z) times Z's own backing ``c_Z``; this is then
    combined (precision-weighted) with the asker's *private* direct opinion of
    ``subject``. The result is a collapsed :class:`SummaryStat` — no author or path
    identity leaves this function.
    """
    weights = transitive_author_weights(store, asker, alpha=alpha, max_hops=max_hops)

    num = 0.0  # Σ w(A,Z) · c_Z · m_Z
    den = 0.0  # Σ w(A,Z) · c_Z   (trust-discounted effective backing)
    for z, w in weights.items():
        if z == subject:
            continue  # an agent's self-edge is not an opinion about itself
        # third-party read: only events the author made network-traversable contribute
        # (minimum-visibility, §11.3 BI-3) — a bilateral opinion never reaches the asker.
        # KNOWN GAP (D-11): `transitive_author_weights` is NOT visibility-filtered —
        # bilateral familiarity still shapes w(asker, z). Fine for private/local use;
        # blocks serving this aggregate to third parties until resolved (see the
        # module-level KNOWN GAP note in model.py).
        opinion = _valence_summary(store, z, subject, visibilities=THIRD_PARTY_VISIBLE)
        if opinion.confidence <= _EPS:
            continue
        effective = w * opinion.confidence
        num += effective * opinion.magnitude
        den += effective
    network = SummaryStat(num / den, den) if den > _EPS else SummaryStat(0.0, 0.0)

    # the asker's own/private opinion of X: the asker is a party, so all visibility
    # classes are theirs to see (no min-visibility filter on the private side).
    private = _valence_summary(store, asker, subject)
    return combine(network, private)
