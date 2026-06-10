"""Versioned event-tag → channel-delta mapping.

An ingested topology event carries a **self-describing, versioned tag payload**
(``topology-event-ingest.md`` §2.4): agent-meaningful tags the author fills in,
validated against a schema version, then mapped to edge accumulator deltas by a
single versioned mapper — so we don't maintain a hard-coded update function per
event type (``topology-layer.md`` §3 is superseded by this).

This module is **pure** (no DB, no IO): it validates a tag payload and maps it to
a list of abstract channel deltas. The ingest service (`topology_ingest`) executes
each delta against the directory store and records the content-less log row.

Magnitudes are carried as **milli-unit integers**, not floats: the tag payload is
the signed block content, and the SDK's JCS canonicalisation deliberately forbids
floats (a canonical-determinism hazard — two platforms can render the same float
differently and break the signature). Integers canonicalise identically
everywhere. ``MILLI = 1000``: ``interaction_magnitude`` ∈ ``[1, 1000]`` encodes
``0.001..1.0``; ``valence`` ∈ ``[-1000, 1000]`` encodes ``-1.0..1.0``. The mapper
converts to float internally; the stored accumulators are floats as before.

v1 tag schema (``"1"``):

    {
      "tag_schema_version": "1",
      "parties": [did_a, did_b],          # the two DIDs the event is between
      "interaction_magnitude": 1..1000,   # milli-units → interaction channel
      "valence": -1000..1000,             # OPTIONAL milli-units: author's feeling
                                          #   about the *other* party → valence channel
      "context": "general"                # OPTIONAL: v1 is always "general"
    }

Mapping (v1):
- ``interaction_magnitude`` → a symmetric **interaction** delta over both parties
  (its backing ``Σw`` is familiarity). Data about both parties.
- ``valence`` (if present) → a directional **valence** delta from the author to the
  *other* party, weighted by ``interaction_magnitude`` (the event's backing), with
  the ratified 1.5× negative asymmetry applied to negative values
  (``negative_valence_value``). Data about the target only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from synpareia.topology.model import INTERACTION_CHANNEL, VALENCE_CHANNEL
from synpareia.topology.readtime import negative_valence_value

if TYPE_CHECKING:
    from collections.abc import Mapping

#: Tag schema versions this mapper understands. Add a version + a branch in
#: ``map_tags`` to evolve the vocabulary without reshaping storage.
SUPPORTED_TAG_VERSIONS: frozenset[str] = frozenset({"1"})

#: Milli-unit scale for the integer-encoded magnitude/valence fields (floats are
#: not JCS-canonicalisable, so the signed wire format uses integers).
MILLI = 1000

#: The v1 tag vocabulary — deny-by-default. Any key outside this set is rejected,
#: so an author cannot stuff arbitrary content into the (content-less) event log
#: by piggy-backing extra keys on the tag payload (legal §11.4 inv. 2).
ALLOWED_TAG_KEYS: frozenset[str] = frozenset(
    {"tag_schema_version", "parties", "interaction_magnitude", "valence", "context"}
)


@dataclass(frozen=True)
class TagMappedEvent:
    """One topology write derived from an event's tags (channel-tagged so the
    ingest service can dispatch to the matching directory primitive).

    For ``interaction`` (symmetric): ``did_a``/``did_b`` are the two parties, ``v``
    is 0.0, ``subjects`` is both. For ``valence`` (directional): ``did_a`` is the
    author (from), ``did_b`` is the target (to), ``w`` is the backing weight, ``v``
    the signed value, ``subjects`` is the target only.
    """

    channel: str
    did_a: str
    did_b: str
    w: float
    v: float
    subjects: tuple[str, ...]


class TagValidationError(ValueError):
    """A tag payload failed schema validation (the ingest maps this to a 422)."""


def _require(cond: bool, msg: str) -> None:  # noqa: FBT001
    if not cond:
        raise TagValidationError(msg)


def validate_tags(payload: Mapping[str, object]) -> str:
    """Validate a tag payload against its declared version; return the version.

    Pure + total: raises :class:`TagValidationError` (never silently coerces) on any
    malformed/out-of-range field, so the ingest can reject before touching the store.
    """
    extra = set(payload.keys()) - ALLOWED_TAG_KEYS
    _require(
        not extra,
        f"unknown tag key(s) {sorted(extra)} — the v1 vocabulary is deny-by-default "
        "(content cannot ride along on extra keys)",
    )
    version = payload.get("tag_schema_version")
    _require(
        isinstance(version, str) and version in SUPPORTED_TAG_VERSIONS,
        f"unsupported tag_schema_version {version!r}; supported: {sorted(SUPPORTED_TAG_VERSIONS)}",
    )
    parties = payload.get("parties")
    _require(
        isinstance(parties, (list, tuple))
        and len(parties) == 2
        and all(isinstance(p, str) and p for p in parties)
        and parties[0] != parties[1],
        "parties must be two distinct non-empty DID strings",
    )
    mag = payload.get("interaction_magnitude")
    _require(
        isinstance(mag, int) and not isinstance(mag, bool) and 0 < mag <= MILLI,
        f"interaction_magnitude must be an integer in (0, {MILLI}] milli-units",
    )
    if "valence" in payload and payload["valence"] is not None:
        val = payload["valence"]
        _require(
            isinstance(val, int) and not isinstance(val, bool) and -MILLI <= val <= MILLI,
            f"valence, if present, must be an integer in [-{MILLI}, {MILLI}] milli-units",
        )
    if "context" in payload and payload["context"] is not None:
        _require(isinstance(payload["context"], str), "context, if present, must be a string")
    return version  # type: ignore[return-value]


def map_tags(payload: Mapping[str, object], author_did: str) -> list[TagMappedEvent]:
    """Map a validated tag payload to channel deltas, authored by ``author_did``.

    ``author_did`` must be one of the two parties (it is the opinion-holder for the
    valence channel; the target is the other party). Raises
    :class:`TagValidationError` on an invalid payload or an author not in parties.
    """
    validate_tags(payload)
    parties: tuple[str, ...] = tuple(payload["parties"])  # type: ignore[arg-type]
    _require(author_did in parties, f"author {author_did!r} is not a party to {parties}")
    mag = float(payload["interaction_magnitude"]) / MILLI  # type: ignore[arg-type]

    events: list[TagMappedEvent] = [
        # symmetric co-occurrence; data about both parties
        TagMappedEvent(
            channel=INTERACTION_CHANNEL,
            did_a=parties[0],
            did_b=parties[1],
            w=mag,
            v=0.0,
            subjects=tuple(parties),
        )
    ]

    valence = payload.get("valence")
    # valence == 0 is "no opinion expressed", treated identically to omitting it: a
    # zero-value delta would add backing (Σw) with no value (Σw·v), diluting the
    # target's confidence-weighted mean toward zero — a score-erosion vector. Only a
    # non-zero valence produces a valence delta.
    if valence is not None and valence != 0:
        target = parties[1] if author_did == parties[0] else parties[0]
        raw = float(valence) / MILLI  # type: ignore[arg-type]
        # ratified 1.5× negative asymmetry on the *value* (negatives count more)
        v = negative_valence_value(-raw) if raw < 0 else raw
        events.append(
            TagMappedEvent(
                channel=VALENCE_CHANNEL,
                did_a=author_did,  # from (opinion-holder)
                did_b=target,  # to (data subject)
                w=mag,
                v=v,
                subjects=(target,),
            )
        )
    return events
