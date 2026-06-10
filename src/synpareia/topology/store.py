"""In-memory edge ledger for topology — uniform per-channel accumulators + ledger.

Production substrate (DB-backed; per ``docs/explorations/topology-production-design.md`` §3)
mirrors this API. This in-memory store is the reference behaviour for the spec
and the erasure mechanism (``topology-erasure-design.md`` §3-4).

Edges are ``EdgePair`` records holding a uniform per-channel ``Moment`` map
(revocable + non-revocable buckets per channel/direction). The
``ContributionLedger`` records each event's ``Moment`` delta so erasure can
subtract exactly a subject's revocable contributions (posture 1) — or, as a
fallback for any update rule, zero an edge's whole revocable bucket (posture 3).
There is deliberately no whole-edge-deletion operation (design rule 2).
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from synpareia.topology.ledger import Contribution, ContributionLedger
from synpareia.topology.model import (
    DEFAULT_VISIBILITY,
    INTERACTION_CHANNEL,
    VALENCE_CHANNEL,
    EdgePair,
    Moment,
    ordered_pair_key,
)
from synpareia.topology.readtime import clamp_valence


@dataclass
class EdgeView:
    """Read-time projection of one direction of an edge (served values).

    ``familiarity`` is the ``interaction`` channel's backing (``Σw``);
    ``valence`` is the ``valence`` channel's clamped magnitude (``Σw·v / Σw``).
    """

    counterpart_did: str
    familiarity: float
    valence: float
    last_event_at: float


class TopologyStore:
    """In-memory topology store with per-channel accumulators + a contribution ledger.

    Edges are stored as ``EdgePair`` records keyed by ``(did_low, did_high)``.
    All updates are atomic at the pair level. An adjacency index makes neighbour
    lookups O(degree). The contribution ledger is the source of truth for
    erasure; the edge accumulators are its materialized projection.
    """

    def __init__(self) -> None:
        self._edges: dict[tuple[str, str], EdgePair] = {}
        self._neighbours_of: dict[str, set[tuple[str, str]]] = {}
        self._ledger = ContributionLedger()

    def _index_edge(self, key: tuple[str, str]) -> None:
        low, high = key
        self._neighbours_of.setdefault(low, set()).add(key)
        self._neighbours_of.setdefault(high, set()).add(key)

    def get_pair(self, did_a: str, did_b: str) -> EdgePair | None:
        """Return the underlying EdgePair for two DIDs, or None if no edge exists."""
        if did_a == did_b:
            return None
        key = ordered_pair_key(did_a, did_b)
        return self._edges.get(key)

    def get_edge(self, from_did: str, to_did: str) -> tuple[float, float] | None:
        """Return **raw** ``(familiarity, valence)`` for ``from_did → to_did`` or None.

        Raw = the storage view (familiarity = interaction backing ``Σw``; valence =
        the valence magnitude ``Σw·v / Σw``, *unclamped*). This is what erasure
        operates against (and what Slice-1 tests assert). For the consumer-facing
        value with read-time nonlinearity applied, use :meth:`get_served_edge`."""
        pair = self.get_pair(from_did, to_did)
        if pair is None:
            return None
        return pair.directional_view(from_did, to_did)

    def get_served_edge(self, from_did: str, to_did: str) -> tuple[float, float] | None:
        """Return the **served** ``(familiarity, valence)`` for ``from_did → to_did``
        with read-time policy applied: valence magnitude clamped to ``[-1, 1]``,
        familiarity left unclamped (monotonic, no ceiling). None if no edge exists.

        The clamp is applied on read only; the stored accumulators stay linear so
        erasure (Slice 1) remains exact (design rule 3). Decay is a later slice."""
        pair = self.get_pair(from_did, to_did)
        if pair is None:
            return None
        fam, val = pair.directional_view(from_did, to_did)
        return (fam, clamp_valence(val))

    # ------------------------------------------------------------------
    # Updates (project the event's moment onto the edge accumulator, then record
    # it in the ledger — both within one synchronous call; the ledger is the
    # source of truth for erasure, the accumulator its materialized projection)
    # ------------------------------------------------------------------

    def _record(
        self,
        channel: str,
        from_did: str,
        to_did: str,
        w: float,
        v: float,
        at: float,
        subjects: tuple[str, ...],
        *,
        event_hash: str | None,
        revocable: bool,
        visibility: str = DEFAULT_VISIBILITY,
    ) -> None:
        """Shared write path: validate, project ``Moment(w, w·v)`` onto the
        channel's accumulator (in the ``visibility`` cell), record the contribution.
        ``subjects`` is the data-subject set for erasure (caller computes it per
        channel semantics)."""
        if event_hash is not None and self._ledger.has(event_hash):
            return  # ingest idempotency
        key = ordered_pair_key(from_did, to_did)
        pair = self._edges.get(key) or EdgePair.new(from_did, to_did)
        self._edges[key] = pair.with_channel_event(
            channel, from_did, to_did, w, v, at, revocable=revocable, visibility=visibility
        )
        self._index_edge(key)
        if event_hash is not None:
            self._ledger.add(
                Contribution(
                    event_hash=event_hash,
                    subjects=subjects,
                    from_did=from_did,
                    to_did=to_did,
                    channel=channel,
                    delta=Moment(sw=w, swv=w * v),
                    revocable=revocable,
                    at=at,
                    visibility=visibility,
                )
            )

    def record_co_interaction(
        self,
        did_a: str,
        did_b: str,
        weight: float = 1.0,
        at: float = 0.0,
        *,
        event_hash: str | None = None,
        subject_did: str | None = None,
        revocable: bool = True,
        visibility: str = DEFAULT_VISIBILITY,
    ) -> None:
        """Record a co-occurrence event (the symmetric ``interaction`` channel,
        whose backing ``Σw`` is familiarity).

        ``weight`` must be finite and non-negative (familiarity is monotonic).
        ``event_hash`` (if given) gives ingest idempotency. Co-occurrence is data
        about *both* parties, so the contribution is recorded under both as data
        subjects — either party's Art. 17 erasure removes the shared fact.
        ``subject_did`` is accepted for API symmetry but, if given, must be one of
        the two parties (locality, design rule 1); the recorded subject set is
        always both.
        """
        if did_a == did_b:
            raise ValueError("co-interaction requires two distinct DIDs")
        if not (weight >= 0) or weight == float("inf"):
            raise ValueError(
                f"co-interaction weight must be finite and non-negative; got {weight}"
            )
        if subject_did is not None and subject_did not in (did_a, did_b):
            raise ValueError(
                f"subject_did {subject_did!r} is not a party to ({did_a}, {did_b}) "
                "— locality invariant (design rule 1)"
            )
        # interaction channel tracks backing only; v=0 (no signed value).
        self._record(
            INTERACTION_CHANNEL,
            did_a,
            did_b,
            weight,
            0.0,
            at,
            (did_a, did_b),
            event_hash=event_hash,
            revocable=revocable,
            visibility=visibility,
        )

    def update_valence(
        self,
        from_did: str,
        to_did: str,
        w: float,
        v: float,
        at: float = 0.0,
        *,
        event_hash: str | None = None,
        subject_did: str | None = None,
        revocable: bool = True,
        visibility: str = DEFAULT_VISIBILITY,
    ) -> None:
        """Record a directional valence event for ``from_did → to_did`` (asymmetric):
        backing weight ``w`` and signed value ``v`` accumulate as ``Moment(w, w·v)``.

        ``w`` must be finite and non-negative (it is the event's backing weight);
        ``v`` must be finite (the signed value; may fall outside ``[-1, 1]`` — the
        served magnitude is clamped read-time). ``event_hash`` gives ingest
        idempotency. A→B valence is data *about* the target, so the subject is the
        target (``to_did``) by default. ``subject_did`` overrides that but, by the
        locality invariant (design rule 1), must be one of the two parties."""
        if from_did == to_did:
            raise ValueError("self-valence not supported")
        if not (w >= 0) or w == float("inf"):
            raise ValueError(f"valence weight w must be finite and non-negative; got {w}")
        if not math.isfinite(v):
            # A non-finite value would poison the linear accumulator: inf saturates
            # Σw·v irreversibly (breaking contribution-subtract erasure) and NaN slips
            # through the read-time clamp (NaN compares False against both bounds),
            # silently violating the served [-1, 1] range. Reject at the source.
            raise ValueError(f"valence value v must be finite; got {v}")
        if subject_did is not None and subject_did != to_did:
            # A directional valence is data *about the target*, so the target is its
            # sole data subject. Accepting subject_did=from_did would let consent
            # derivation + erasure key off the opinion-holder instead of the target —
            # a laundering hole (a record about B made non-erasable via A's consent,
            # which B could never reach). The subject of a valence is to_did, full stop.
            raise ValueError(
                f"subject_did {subject_did!r} must be the valence target {to_did!r}: "
                "a directional valence's sole data subject is its target."
            )
        subject = subject_did if subject_did is not None else to_did
        self._record(
            VALENCE_CHANNEL,
            from_did,
            to_did,
            w,
            v,
            at,
            (subject,),
            event_hash=event_hash,
            revocable=revocable,
            visibility=visibility,
        )

    # ------------------------------------------------------------------
    # Erasure (posture 1: contribution-subtract; posture 3: bucket-zero)
    # ------------------------------------------------------------------

    def erase_contributions(self, subject_did: str) -> int:
        """Posture 1 — subtract every *revocable* contribution of ``subject_did``
        from the affected edges (the non-revocable bucket is untouched), then drop
        those ledger entries. Idempotent (hash-keyed) and locality-preserving
        (only edges the subject is party to are touched). Returns the count erased.

        Channel-agnostic: each contribution carries its ``Moment`` delta and the
        channel it touched; ``with_moment_subtracted`` re-derives symmetric-vs-
        directional from the channel, so there is no per-kind dispatch to drift.
        Because updates are additive, subtracting a contribution's moment yields
        exactly the edge that would exist had the event never happened.
        """
        erased = 0
        for c in self._ledger.revocable_contributions_of(subject_did):
            key = ordered_pair_key(c.from_did, c.to_did)
            pair = self._edges.get(key)
            if pair is not None:
                self._edges[key] = pair.with_moment_subtracted(
                    c.channel,
                    c.from_did,
                    c.to_did,
                    c.delta,
                    revocable=True,
                    visibility=c.visibility,
                )
            self._ledger.remove(c.event_hash)
            erased += 1
        return erased

    def zero_revocable_bucket(self, did_a: str, did_b: str) -> None:
        """Posture 3 fallback — zero the entire revocable bucket of one edge (all
        channels), leaving the non-revocable bucket intact. Works for *any* update
        rule (no per-contribution arithmetic). Coarser than ``erase_contributions``
        (over-erases the other party's revocable side too) but always available."""
        key = ordered_pair_key(did_a, did_b)
        pair = self._edges.get(key)
        if pair is None:
            return
        self._edges[key] = pair.with_revocable_bucket_zeroed()
        # drop revocable ledger entries for this pair (both subjects' revocable deltas)
        for c in list(self._ledger.revocable_for_pair(did_a, did_b)):
            self._ledger.remove(c.event_hash)

    # ------------------------------------------------------------------
    # Reads
    # ------------------------------------------------------------------

    def edges_for(self, did: str) -> list[EdgeView]:
        """List all edges involving ``did`` as outgoing (served) views. O(degree).

        Iterates neighbour keys in **canonical (did_low, did_high) order** — `sorted`,
        not raw set order — so neighbour expansion is deterministic across process runs
        and matches the directory mirror's `edges_for` (`ORDER BY did_low, did_high`).
        Without this, BFS tie-breaking (``shortest_path``) was hash-seed-dependent and
        diverged from the directory's reproducible pick (verified by the verify-fanout)."""
        views: list[EdgeView] = []
        for key in sorted(self._neighbours_of.get(did, ())):
            pair = self._edges[key]
            low, high = key
            counterpart = high if did == low else low
            fam, val = pair.directional_view(did, counterpart)
            views.append(
                EdgeView(
                    counterpart_did=counterpart,
                    familiarity=fam,  # interaction backing; unclamped (monotonic)
                    valence=clamp_valence(val),  # served: read-time clamp to [-1, 1]
                    last_event_at=pair.last_event_at,
                )
            )
        return views

    def neighbours(self, did: str, *, min_familiarity: float = 0.0) -> list[str]:
        """Return DIDs connected to ``did`` with served familiarity above threshold."""
        return [
            view.counterpart_did
            for view in self.edges_for(did)
            if view.familiarity > min_familiarity
        ]

    def all_dids(self) -> set[str]:
        """Return the set of all DIDs that appear in any edge."""
        dids: set[str] = set()
        for low, high in self._edges:
            dids.add(low)
            dids.add(high)
        return dids
