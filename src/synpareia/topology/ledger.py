"""Contribution ledger — the minimal-sufficient-set for surgical erasure.

Per docs/explorations/topology-erasure-design.md §4 (posture 1,
contribution-subtract): the edge accumulators are a materialized projection of
a list of per-event *deltas*. To erase a subject's contribution we don't need
the event content — only its ``(event_hash, subjects, delta, revocable)``.
This is *lighter* than retaining whole events (Art. 5(1)(c) minimisation) and
gives surgical, idempotent, locality-preserving erasure (Art. 17).

The ledger holds one entry per witnessed event that touched an edge. The
``event_hash`` is the idempotency key for BOTH ingest (don't double-count a
re-delivered event) and erasure (don't double-subtract on a replayed request).

A contribution can have **more than one data subject**: a valence delta is data
*about the target* (one subject), but a symmetric co-occurrence (familiarity) is
data about *both* parties (two subjects) — either party's Art. 17 request must be
able to remove the shared fact. ``subjects`` carries that set; ``remove`` drops
the entry from every subject's index so erasure stays idempotent across subjects
(once removed, a second subject's erasure finds nothing — no double-subtract).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .model import DEFAULT_VISIBILITY

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .model import Moment


@dataclass(frozen=True)
class Contribution:
    """One event's moment-delta to an edge — the unit of erasure.

    ``channel`` is the characteristic this event touched (``"interaction"``,
    ``"valence"``, …). ``delta`` is the ``Moment`` (``Σw, Σw·v``) the event added;
    erasure subtracts exactly this from the channel's accumulator. Whether the
    subtraction is symmetric (both directions) or directional (``from→to`` only)
    is re-derived from the channel (``model.is_symmetric``), so the ledger entry
    stays channel-agnostic. ``subjects`` are the data subjects whose erasure may
    remove this contribution. ``visibility`` is the may-deliver class the event
    landed in (``bilateral`` / ``network_traversable``) — carried so erasure
    subtracts from the exact cell the event added to (the accumulator is keyed by
    visibility, ``model._CellKey``).
    """

    event_hash: str
    subjects: tuple[str, ...]
    from_did: str
    to_did: str
    channel: str
    delta: Moment
    revocable: bool
    at: float
    visibility: str = DEFAULT_VISIBILITY


class ContributionLedger:
    """Ledger of per-event deltas, indexed for erasure.

    Lifecycle is **add-then-remove-on-erase**, not append-only: a contribution
    is added on ingest (idempotent by ``event_hash``) and removed when its delta
    is subtracted during an Art. 17 erasure. Removal-on-erase is what keeps
    erasure idempotent — once a contribution is gone, a replayed erase request
    (or a second subject's erase of a shared contribution) finds nothing to
    subtract. (Note: at the substrate layer the witnessed *event log* is the
    durable append-only record; this in-memory ledger is the erasure index over
    the contributions currently projected into the accumulators.)

    Indices:
    - ``_entries`` — by ``event_hash``; ingest idempotency (a hash already
      present is a no-op).
    - ``_by_subject`` — erasure lookup: every contribution a subject can erase.
    """

    def __init__(self) -> None:
        self._entries: dict[str, Contribution] = {}  # event_hash -> Contribution
        self._by_subject: dict[str, set[str]] = {}  # subject_did -> {event_hash}

    def has(self, event_hash: str) -> bool:
        return event_hash in self._entries

    def add(self, contribution: Contribution) -> bool:
        """Record a contribution. Returns False (no-op) if its hash is already
        present — ingest idempotency. Returns True if newly added."""
        if contribution.event_hash in self._entries:
            return False
        self._entries[contribution.event_hash] = contribution
        for subject in contribution.subjects:
            self._by_subject.setdefault(subject, set()).add(contribution.event_hash)
        return True

    def revocable_contributions_of(self, subject_did: str) -> list[Contribution]:
        """All *revocable* contributions a subject may erase (Art. 17). The
        non-revocable bucket is deliberately excluded — it survives erasure."""
        return [
            self._entries[h]
            for h in self._by_subject.get(subject_did, set())
            if self._entries[h].revocable
        ]

    def revocable_for_pair(self, from_did: str, to_did: str) -> Iterable[Contribution]:
        """All revocable contributions touching the edge between two DIDs
        (either direction). Used by the posture-3 bucket-zero fallback so it
        doesn't reach into the ledger's internals."""
        pair = frozenset((from_did, to_did))
        return [
            c
            for c in self._entries.values()
            if c.revocable and frozenset((c.from_did, c.to_did)) == pair
        ]

    def remove(self, event_hash: str) -> None:
        """Drop a contribution from the ledger (after its delta is subtracted).
        Removes it from *every* subject's index, so a second subject's erasure
        of a shared contribution finds nothing (idempotent across subjects)."""
        entry = self._entries.pop(event_hash, None)
        if entry is not None:
            for subject in entry.subjects:
                idx = self._by_subject.get(subject)
                if idx is not None:
                    idx.discard(event_hash)
                    if not idx:
                        # drop now-empty subject keys so a long-lived store
                        # doesn't accrete empty sets over many erasures
                        del self._by_subject[subject]
