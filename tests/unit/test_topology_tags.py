"""Unit tests for the versioned tag → channel-delta mapper (`topology.tags`).

The mapper is the pure boundary between agent-meaningful event tags and the edge
accumulator deltas the directory store applies. These tests pin: schema validation
(fail-closed on malformed/out-of-range fields, integer-only milli-units since the
signed wire format can't carry floats), the v1 mapping (interaction + optional
valence), the ratified 1.5× negative asymmetry, and subject assignment
(interaction → both parties; valence → target only).
"""

from __future__ import annotations

import pytest

from synpareia.topology import (
    INTERACTION_CHANNEL,
    NEGATIVE_VALENCE_WEIGHT,
    VALENCE_CHANNEL,
    TagValidationError,
    map_tags,
    validate_tags,
)
from synpareia.topology.tags import MILLI

DID_A = "did:key:zAlice"
DID_B = "did:key:zBob"


def _base(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "tag_schema_version": "1",
        "parties": [DID_A, DID_B],
        "interaction_magnitude": 500,  # 0.5 in milli-units
    }
    payload.update(overrides)
    return payload


# --- validation -----------------------------------------------------------


def test_validate_returns_version() -> None:
    assert validate_tags(_base()) == "1"


@pytest.mark.parametrize(
    "payload",
    [
        {"parties": [DID_A, DID_B], "interaction_magnitude": 500},  # no version
        _base(tag_schema_version="0"),  # unsupported version
        _base(tag_schema_version=1),  # version must be str
        _base(parties=[DID_A]),  # one party
        _base(parties=[DID_A, DID_A]),  # not distinct
        _base(parties=[DID_A, ""]),  # empty did
        _base(interaction_magnitude=0),  # must be > 0
        _base(interaction_magnitude=1001),  # must be <= 1000
        _base(interaction_magnitude=0.5),  # floats are not JCS-canonicalisable → rejected
        _base(interaction_magnitude=True),  # bool is not a magnitude
        _base(valence=1500),  # out of range
        _base(valence=0.5),  # float rejected
        _base(valence="hot"),  # wrong type
        _base(context=123),  # context must be str
        _base(conversation_content="secret leak"),  # extra key — content cannot ride along
        _base(user_pii={"name": "x"}),  # extra key (any shape)
    ],
)
def test_validate_rejects_malformed(payload: dict[str, object]) -> None:
    with pytest.raises(TagValidationError):
        validate_tags(payload)


def test_extra_keys_rejected_deny_by_default() -> None:
    """The v1 vocabulary is deny-by-default: an author cannot smuggle content into
    the content-less log by adding extra tag keys (legal §11.4 inv. 2)."""
    with pytest.raises(TagValidationError, match="unknown tag key"):
        validate_tags(_base(free_text="a wall of conversation content"))


def test_valence_none_is_allowed() -> None:
    assert validate_tags(_base(valence=None)) == "1"


# --- mapping --------------------------------------------------------------


def test_interaction_only_maps_to_one_symmetric_delta() -> None:
    events = map_tags(_base(interaction_magnitude=700), author_did=DID_A)
    assert len(events) == 1
    ev = events[0]
    assert ev.channel == INTERACTION_CHANNEL
    assert {ev.did_a, ev.did_b} == {DID_A, DID_B}
    assert ev.w == pytest.approx(0.7)  # 700 milli → 0.7
    assert ev.v == 0.0
    assert set(ev.subjects) == {DID_A, DID_B}


def test_valence_adds_directional_delta_about_target() -> None:
    events = map_tags(_base(interaction_magnitude=400, valence=600), author_did=DID_A)
    assert len(events) == 2
    valence = next(e for e in events if e.channel == VALENCE_CHANNEL)
    assert valence.did_a == DID_A  # from = author (opinion-holder)
    assert valence.did_b == DID_B  # to = target
    assert valence.w == pytest.approx(0.4)  # backed by interaction magnitude
    assert valence.v == pytest.approx(0.6)
    assert valence.subjects == (DID_B,)  # data about the target only


def test_valence_target_is_other_party_when_author_is_b() -> None:
    events = map_tags(_base(valence=300), author_did=DID_B)
    valence = next(e for e in events if e.channel == VALENCE_CHANNEL)
    assert valence.did_a == DID_B  # author
    assert valence.did_b == DID_A  # target
    assert valence.subjects == (DID_A,)


def test_negative_valence_applies_ratified_asymmetry() -> None:
    events = map_tags(_base(valence=-400), author_did=DID_A)
    valence = next(e for e in events if e.channel == VALENCE_CHANNEL)
    # negatives count 1.5× on the value: -0.4 * 1.5
    assert valence.v == pytest.approx(-0.4 * NEGATIVE_VALENCE_WEIGHT)
    assert valence.v < 0


def test_positive_valence_is_unscaled() -> None:
    events = map_tags(_base(valence=400), author_did=DID_A)
    valence = next(e for e in events if e.channel == VALENCE_CHANNEL)
    assert valence.v == pytest.approx(0.4)


def test_zero_valence_emits_no_valence_delta() -> None:
    """valence=0 is "no opinion" — it must not produce a zero-value valence delta
    (which would dilute the target's mean). Only the interaction delta is emitted."""
    events = map_tags(_base(valence=0), author_did=DID_A)
    assert len(events) == 1
    assert events[0].channel == INTERACTION_CHANNEL
    assert not any(e.channel == VALENCE_CHANNEL for e in events)


def test_author_must_be_a_party() -> None:
    with pytest.raises(TagValidationError):
        map_tags(_base(), author_did="did:key:zEve")


def test_map_rejects_malformed_before_touching_parties() -> None:
    with pytest.raises(TagValidationError):
        map_tags(_base(interaction_magnitude=2000), author_did=DID_A)


def test_mapped_events_are_immutable() -> None:
    ev = map_tags(_base(), author_did=DID_A)[0]
    with pytest.raises((AttributeError, TypeError)):
        ev.w = 9.9  # type: ignore[misc]


def test_full_scale_magnitude_maps_to_one() -> None:
    # boundary: magnitude == MILLI is valid → w == 1.0
    ev = map_tags(_base(interaction_magnitude=MILLI), author_did=DID_A)[0]
    assert ev.w == pytest.approx(1.0)
