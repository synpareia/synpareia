"""Topology data model — one record per ordered DID pair, uniform per-channel
linear-sufficient-statistic accumulators.

Every relational characteristic is a **channel** with the *same* shape: per
``(channel, direction, bucket)`` we store a ``Moment`` — the linear sums
sufficient to reconstruct that channel's summary statistics later. There are no
special-cased properties: ``familiarity`` is simply the backing (``Σw``) of the
symmetric ``interaction`` channel; ``valence`` is a directional channel whose
served magnitude is ``Σw·v / Σw`` and whose confidence is ``Σw``. Adding a new
channel (calibration, good-faith, …) is zero-schema-work.

Two stages, two obligations (``docs/explorations/topology-function-contracts.md``
§4):

- **Accumulators** (here): linear, excisable sufficient statistics. A ``Moment``
  is ``(Σw, Σw·v)`` — additive, so erasure is a subtraction and the stored state
  stays linear (design rule 3, ``topology-erasure-design.md`` §9).
- **Summary statistics** (read-time, the store / aggregate layer): possibly
  non-linear functions over the accumulators. ``magnitude`` / ``confidence`` here
  are *instrumental* read-offs, not the final served product.

Each channel/direction is split into a **revocable** and a **non-revocable**
bucket; the served value sums both, erasure only ever touches the revocable
bucket (``topology-erasure-design.md`` §3). The accumulators are a materialized
projection of the contribution ledger (``ledger.py``), which is the source of
truth for erasure.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

# Channel registry. Symmetric channels (co-occurrence) write both directions
# equally; directional channels write only the from→to view. ``interaction`` is
# the symmetric backing channel whose Σw *is* familiarity. Adding a channel here
# (+ a tag→delta mapping in the ingest layer) is the whole cost of a new
# characteristic — the storage shape is uniform.
INTERACTION_CHANNEL = "interaction"
VALENCE_CHANNEL = "valence"
SYMMETRIC_CHANNELS: frozenset[str] = frozenset({INTERACTION_CHANNEL})

_LOW_TO_HIGH = "low_to_high"
_HIGH_TO_LOW = "high_to_low"
_REVOCABLE = "revocable"
_NON_REVOCABLE = "non_revocable"

# Visibility classes — the may-deliver dimension (``topology-event-delivery.md`` §1,
# ``transmission-policy-schema.md``). v1 uses two: ``bilateral`` (only the two
# parties may see the event) and ``network_traversable`` (any in-ecosystem asker
# may). It is a **cell-key dimension** so a visibility-filtered read serves only the
# permitted classes without per-event recomputation — the §11.3 minimum-visibility
# control (BI-3). Orthogonal to the revocable/non-revocable (erasure) bucket.
# KNOWN GAP (audit D-11, pre-consumer): only *valence opinions* are visibility-
# filtered today; the transitive familiarity walk (`transitive_author_weights`)
# sums across all visibility classes, so a *served* aggregate could leak
# bilateral-edge existence via reachability. Resolve before any consumer serves.
VISIBILITY_BILATERAL = "bilateral"
VISIBILITY_NETWORK_TRAVERSABLE = "network_traversable"
#: Fail-closed default: an event stays third-party-invisible (``bilateral``) unless
#: ``may-deliver`` consent promotes it to ``network_traversable`` (the ingest sets
#: it; an event with no may-deliver authorisation is never served to a third party).
DEFAULT_VISIBILITY = VISIBILITY_BILATERAL
#: Visibility classes a third-party asker (not a party to the edge) may see.
THIRD_PARTY_VISIBLE: frozenset[str] = frozenset({VISIBILITY_NETWORK_TRAVERSABLE})

# Float-residual tolerance. Contribution-subtract over non-exact float weights can
# leave a machine-epsilon residual rather than exact zero (e.g. 0.1+0.2+0.3-0.1-0.2-0.3
# ≈ 8e-17, not 0.0). A cell that subtracts to within this of empty is snapped to
# *empty*, so (a) the sparse map drops it — no stale cell/row after full erasure — and
# (b) the magnitude ratio Σw·v/Σw can't amplify a tiny residual into a non-zero served
# value (8e-17/8e-17 ≈ 0.08). 1e-9 sits ~7 orders above machine epsilon and well below
# any plausible real interaction weight, so it never snaps a genuine accumulator.
_EPS = 1e-9


def is_symmetric(channel: str) -> bool:
    """True if a channel writes both directions equally (co-occurrence-like)."""
    return channel in SYMMETRIC_CHANNELS


def ordered_pair_key(did_a: str, did_b: str) -> tuple[str, str]:
    """Return ``(low, high)`` lexicographic order for two DIDs.

    Raises ``ValueError`` if the two DIDs are equal (no self-edges in v0).
    """
    if did_a == did_b:
        raise ValueError("self-edges not supported in v0")
    if did_a < did_b:
        return (did_a, did_b)
    return (did_b, did_a)


@dataclass(frozen=True)
class Moment:
    """Linear sufficient statistics for one ``(channel, direction, bucket)`` cell.

    ``sw`` = ``Σw`` (backing weight → the confidence input). ``swv`` = ``Σw·v``
    (magnitude numerator). Both are plain additive sums, so combining and erasing
    are ``+`` / ``-`` and the stored state stays linear. Further sums (e.g.
    ``Σw·v²`` for a variance-based confidence) are an additive extension when a
    summary statistic needs them — not stored until then (contracts §2a).
    """

    sw: float = 0.0
    swv: float = 0.0

    def __add__(self, other: Moment) -> Moment:
        return Moment(self.sw + other.sw, self.swv + other.swv)

    def __sub__(self, other: Moment) -> Moment:
        return Moment(self.sw - other.sw, self.swv - other.swv)

    @property
    def magnitude(self) -> float:
        """Backing-weighted mean value ``Σw·v / Σw`` (0.0 when unbacked). Raw —
        read-time clamping is the store's concern. A negligible backing (``|Σw|`` below
        the float-residual tolerance) reads as 0.0, so a post-erasure residual can't be
        amplified by the ratio into a spurious served value."""
        return self.swv / self.sw if abs(self.sw) > _EPS else 0.0

    @property
    def confidence(self) -> float:
        """Instrumental backing-weight read-off ``Σw``. The *served* confidence is
        a (possibly non-linear) function chosen at summary stage (contracts §4)."""
        return self.sw


_ZERO = Moment()
# A cell key is (channel, direction, bucket, visibility).
_CellKey = tuple[str, str, str, str]


def _is_negligible(m: Moment) -> bool:
    """True if a moment is within the float-residual tolerance of empty (so it should
    be dropped from the sparse map rather than left as a machine-epsilon stale cell)."""
    return abs(m.sw) < _EPS and abs(m.swv) < _EPS


@dataclass(frozen=True)
class EdgePair:
    """One record per ordered DID pair: a uniform map of per-channel ``Moment``
    accumulators, plus the last-event timestamp.

    Keys are ``(channel, direction, bucket, visibility)`` where direction ∈
    ``{low_to_high, high_to_low}``, bucket ∈ ``{revocable, non_revocable}`` (the
    erasure dimension), and visibility ∈ ``{bilateral, network_traversable}`` (the
    may-deliver dimension — orthogonal to the bucket). Symmetric channels
    (``interaction``) carry equal moments in both directions; directional channels
    (``valence``) differ per direction. Raw reads sum over bucket *and* visibility;
    only the aggregate's third-party read filters visibility
    (:meth:`served_moment_visible`). The map is treated immutably — every update
    returns a new ``EdgePair`` (frozen value object).
    """

    did_low: str
    did_high: str
    moments: Mapping[_CellKey, Moment] = field(default_factory=dict)
    last_event_at: float = 0.0

    def __post_init__(self) -> None:
        # Make the moment map genuinely read-only so the "frozen value object" contract
        # holds in substance: frozen=True only blocks rebinding (pair.moments = ...), not
        # in-place mutation (pair.moments[k] = v). All updates go through with_*/replace,
        # which build a fresh dict that this re-wraps. (EdgePair is always used as a value,
        # never a dict key, so its consequent unhashability is fine.)
        if not isinstance(self.moments, MappingProxyType):
            object.__setattr__(self, "moments", MappingProxyType(dict(self.moments)))

    @classmethod
    def new(cls, did_a: str, did_b: str) -> EdgePair:
        low, high = ordered_pair_key(did_a, did_b)
        return cls(did_low=low, did_high=high)

    def _check(self, from_did: str, to_did: str) -> bool:
        """Validate the DIDs match this pair; return True iff from_did is the low side."""
        low, high = ordered_pair_key(from_did, to_did)
        if (low, high) != (self.did_low, self.did_high):
            raise ValueError(
                f"DIDs ({from_did}, {to_did}) don't match this pair "
                f"({self.did_low}, {self.did_high})"
            )
        return from_did == self.did_low

    def _direction(self, from_did: str, to_did: str) -> str:
        return _LOW_TO_HIGH if self._check(from_did, to_did) else _HIGH_TO_LOW

    def _cell(self, channel: str, direction: str, bucket: str, visibility: str) -> Moment:
        return self.moments.get((channel, direction, bucket, visibility), _ZERO)

    def _bucket_moment(self, channel: str, direction: str, bucket: str) -> Moment:
        """Sum a ``(channel, direction, bucket)`` cell over **all** visibility classes
        (the visibility dimension is invisible to the raw/erasure reads — only the
        aggregate's third-party read filters it, via :meth:`served_moment_visible`)."""
        total = _ZERO
        for (ch, d, b, _vis), moment in self.moments.items():
            if ch == channel and d == direction and b == bucket:
                total = total + moment
        return total

    # ------------------------------------------------------------------
    # Read accessors (per-bucket + served sum), per channel
    # ------------------------------------------------------------------

    def revocable_moment(self, channel: str, from_did: str, to_did: str) -> Moment:
        return self._bucket_moment(channel, self._direction(from_did, to_did), _REVOCABLE)

    def non_revocable_moment(self, channel: str, from_did: str, to_did: str) -> Moment:
        return self._bucket_moment(channel, self._direction(from_did, to_did), _NON_REVOCABLE)

    def served_moment(self, channel: str, from_did: str, to_did: str) -> Moment:
        """Sum of both buckets (and all visibility classes) for the directed view of a
        channel (raw — the visibility-unaware read used by erasure, path ops, and the
        asker's own/private edge)."""
        return self.revocable_moment(channel, from_did, to_did) + self.non_revocable_moment(
            channel, from_did, to_did
        )

    def served_moment_visible(
        self, channel: str, from_did: str, to_did: str, visibilities: frozenset[str]
    ) -> Moment:
        """Sum of both buckets for the directed view, **restricted to** the given
        visibility classes — the minimum-visibility filter (§11.3 BI-3). A third-party
        read passes only the classes it may see (``THIRD_PARTY_VISIBLE``); the asker's
        own/private edge uses the unrestricted :meth:`served_moment`.

        Note this filter covers reads that go *through this method*; the transitive
        familiarity walk does not yet use it (audit D-11) — see the module-level
        KNOWN GAP note on the visibility constants."""
        direction = self._direction(from_did, to_did)
        total = _ZERO
        for (ch, d, _b, vis), moment in self.moments.items():
            if ch == channel and d == direction and vis in visibilities:
                total = total + moment
        return total

    # Familiarity = the interaction channel's served backing (Σw). No special
    # storage — it is the confidence dimension of the symmetric interaction
    # channel, exposed for pathfinding (topology-function-contracts.md §4a).
    def served_familiarity(self, from_did: str, to_did: str) -> float:
        return self.served_moment(INTERACTION_CHANNEL, from_did, to_did).sw

    def revocable_familiarity(self, from_did: str, to_did: str) -> float:
        return self.revocable_moment(INTERACTION_CHANNEL, from_did, to_did).sw

    def non_revocable_familiarity(self, from_did: str, to_did: str) -> float:
        return self.non_revocable_moment(INTERACTION_CHANNEL, from_did, to_did).sw

    # Valence served value = the valence channel's magnitude (Σw·v / Σw). Raw;
    # read-time clamp is the store's concern.
    def served_valence(self, from_did: str, to_did: str) -> float:
        return self.served_moment(VALENCE_CHANNEL, from_did, to_did).magnitude

    def served_valence_confidence(self, from_did: str, to_did: str) -> float:
        return self.served_moment(VALENCE_CHANNEL, from_did, to_did).confidence

    def revocable_valence(self, from_did: str, to_did: str) -> float:
        """Magnitude of the revocable valence bucket (used by the erasure flow)."""
        return self.revocable_moment(VALENCE_CHANNEL, from_did, to_did).magnitude

    def non_revocable_valence(self, from_did: str, to_did: str) -> float:
        """Magnitude of the non-revocable valence bucket (survives erasure)."""
        return self.non_revocable_moment(VALENCE_CHANNEL, from_did, to_did).magnitude

    def directional_view(self, from_did: str, to_did: str) -> tuple[float, float]:
        """Served ``(familiarity, valence)`` for ``from_did → to_did`` (raw).

        Familiarity = interaction backing; valence = valence magnitude.
        Back-compatible 2-tuple signature for the path/edge consumers.
        """
        return (
            self.served_familiarity(from_did, to_did),
            self.served_valence(from_did, to_did),
        )

    # ------------------------------------------------------------------
    # Additive updates (one channel at a time, linear — design rule 3/5)
    # ------------------------------------------------------------------

    def with_channel_event(
        self,
        channel: str,
        from_did: str,
        to_did: str,
        w: float,
        v: float,
        at: float,
        *,
        revocable: bool = True,
        visibility: str = DEFAULT_VISIBILITY,
    ) -> EdgePair:
        """Return a new EdgePair with the ``(w, w·v)`` moment of one event added
        to ``channel``'s accumulator(s), in the chosen bucket **and visibility class**.
        Symmetric channels update both directions; directional channels update only
        ``from→to``.

        Linear: the cell's ``Moment`` gains ``Moment(sw=w, swv=w·v)``. For the
        interaction (familiarity) channel callers pass ``v`` irrelevant (it tracks
        backing ``Σw``); ``record_co_interaction`` passes ``v=0``. ``visibility``
        defaults fail-closed to ``bilateral`` — the ingest promotes it to
        ``network_traversable`` only when may-deliver consent is present.
        """
        is_low = self._check(from_did, to_did)
        bucket = _REVOCABLE if revocable else _NON_REVOCABLE
        delta = Moment(sw=w, swv=w * v)
        directions: tuple[str, ...]
        if is_symmetric(channel):
            directions = (_LOW_TO_HIGH, _HIGH_TO_LOW)
        else:
            directions = (_LOW_TO_HIGH if is_low else _HIGH_TO_LOW,)
        new_moments = dict(self.moments)
        for direction in directions:
            key = (channel, direction, bucket, visibility)
            new_moments[key] = new_moments.get(key, _ZERO) + delta
        return replace(
            self,
            moments=new_moments,
            last_event_at=max(self.last_event_at, at),
        )

    def with_moment_subtracted(
        self,
        channel: str,
        from_did: str,
        to_did: str,
        delta: Moment,
        *,
        revocable: bool = True,
        visibility: str = DEFAULT_VISIBILITY,
    ) -> EdgePair:
        """Return a new EdgePair with ``delta`` subtracted from ``channel``'s
        accumulator(s) (the inverse of one event's contribution — erasure,
        posture 1). Symmetric channels subtract from both directions; directional
        from ``from→to`` only. ``visibility`` selects the cell the event landed in
        (the contribution carries it). Buckets that hit empty are dropped to keep the
        map sparse."""
        is_low = self._check(from_did, to_did)
        bucket = _REVOCABLE if revocable else _NON_REVOCABLE
        directions: tuple[str, ...]
        if is_symmetric(channel):
            directions = (_LOW_TO_HIGH, _HIGH_TO_LOW)
        else:
            directions = (_LOW_TO_HIGH if is_low else _HIGH_TO_LOW,)
        new_moments = dict(self.moments)
        for direction in directions:
            key = (channel, direction, bucket, visibility)
            result = new_moments.get(key, _ZERO) - delta
            if _is_negligible(result):
                # snap a fully-cancelled cell to empty (float residual ≉ exact 0.0)
                new_moments.pop(key, None)
            else:
                new_moments[key] = result
        return replace(self, moments=new_moments)

    def with_revocable_bucket_zeroed(self) -> EdgePair:
        """Return a new EdgePair with every revocable cell (all channels/directions)
        zeroed, the non-revocable buckets untouched (posture-3 erasure fallback,
        ``topology-erasure-design.md`` §4). Drops the revocable cell in *every*
        visibility class (``key[2]`` is the bucket position in the
        ``(channel, direction, bucket, visibility)`` key — visibility-agnostic)."""
        new_moments = {key: m for key, m in self.moments.items() if key[2] != _REVOCABLE}
        return replace(self, moments=new_moments)
