"""Local-only tests for ``synpareia.profile.card``.

Covers the dataclass-based AgentCard surface: build_agent_card,
sign_agent_card, verify_agent_card, card_canonical_bytes. No
network. No pydantic.
"""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

from synpareia.identity import Profile, generate
from synpareia.profile import (
    A2AAuthentication,
    A2ACapabilities,
    FirstContactFee,
    PersistenceOptIn,
    WellKnownPublicationPolicy,
    build_agent_card,
    card_canonical_bytes,
    sign_agent_card,
    verify_agent_card,
)


class TestBuildAgentCard:
    def test_minimal_card_has_identity_layer(self) -> None:
        profile = generate()
        card = build_agent_card(profile, name="Alice")
        assert card.id == profile.id
        assert card.public_key_b64 == base64.b64encode(profile.public_key).decode("ascii")
        assert card.name == "Alice"
        assert card.synpareia.schema_version == "1.0"

    def test_did_matches_sha256_of_public_key(self) -> None:
        profile = generate()
        card = build_agent_card(profile, name="Bob")
        derived = "did:synpareia:" + hashlib.sha256(profile.public_key).hexdigest()
        assert card.id == derived

    def test_synpareia_extensions_populated(self) -> None:
        profile = generate()
        card = build_agent_card(
            profile,
            name="Carol",
            role_tag="supply",
            first_contact_fee=FirstContactFee(credits=10),
            persistence=PersistenceOptIn(
                opted_in_at="2026-05-05T00:00:00+00:00",
                scope=["card_history"],
            ),
            accepted_payment_rails=["stripe", "x402"],
            well_known_publication=WellKnownPublicationPolicy(
                a2a_standard_fields=["name", "skills"]
            ),
            model_family="claude",
            domain_expertise=["mediation"],
            reasoning_style={"depth": "deliberative"},
        )
        assert card.synpareia.role_tag == "supply"
        assert card.synpareia.first_contact_fee == FirstContactFee(credits=10)
        assert card.synpareia.persistence is not None
        assert card.synpareia.persistence.scope == ["card_history"]
        assert card.synpareia.accepted_payment_rails == ["stripe", "x402"]
        assert card.synpareia.well_known_publication is not None
        assert card.synpareia.model_family == "claude"


class TestCardCanonicalBytes:
    def test_canonical_bytes_round_trips_via_json(self) -> None:
        profile = generate()
        card = build_agent_card(profile, name="Dave")
        bytes_ = card_canonical_bytes(card)
        parsed = json.loads(bytes_.decode("utf-8"))

        assert parsed["id"] == profile.id
        assert parsed["name"] == "Dave"
        assert parsed["public_key_b64"] == card.public_key_b64
        assert parsed["extensions"]["synpareia"]["schema_version"] == "1.0"

    def test_canonical_bytes_are_deterministic(self) -> None:
        profile = generate()
        card = build_agent_card(profile, name="Erin")
        b1 = card_canonical_bytes(card)
        b2 = card_canonical_bytes(card)
        assert b1 == b2

    def test_well_known_policy_serialised_under_policies_key(self) -> None:
        profile = generate()
        card = build_agent_card(
            profile,
            name="Frank",
            well_known_publication=WellKnownPublicationPolicy(
                a2a_standard_fields=["name", "version"]
            ),
        )
        parsed = json.loads(card_canonical_bytes(card).decode("utf-8"))
        syn = parsed["extensions"]["synpareia"]
        assert "policies" in syn
        assert syn["policies"]["well_known_publication"]["a2a_standard_fields"] == [
            "name",
            "version",
        ]


class TestIdentityLayerBinding:
    """``build_agent_card`` enforces ``profile.id == sha256(public_key)``."""

    def test_card_id_derived_from_public_key_not_profile_id(self) -> None:
        """If a caller hands us a Profile whose ``id`` field disagrees
        with ``sha256(public_key).hex()``, build_agent_card must
        refuse rather than silently emit a card the directory will
        reject at publish time."""
        good = generate()
        assert good.private_key is not None

        # Inconsistent profile: same key, but a fake DID.
        bad = Profile(
            id="did:synpareia:" + "0" * 64,
            public_key=good.public_key,
            private_key=good.private_key,
        )

        with pytest.raises(ValueError, match="disagrees with did derived"):
            build_agent_card(bad, name="Inconsistent")

    def test_card_id_overrides_with_derived_did(self) -> None:
        """Even if the caller passes a consistent Profile, the card's
        ``id`` is the freshly-derived DID (not whatever was on
        ``profile.id``). Cheap defence in depth — the binding is one
        line, never two."""
        profile = generate()
        card = build_agent_card(profile, name="Mary")
        assert card.id == profile.id  # consistent case


class TestA2AStandardFields:
    """``capabilities`` and ``authentication`` round-trip in canonical bytes."""

    def test_default_capabilities_serialise_camel_case(self) -> None:
        profile = generate()
        card = build_agent_card(profile, name="Nick")
        parsed = json.loads(card_canonical_bytes(card).decode("utf-8"))
        assert parsed["capabilities"] == {"streaming": False, "pushNotifications": False}
        assert parsed["authentication"] == {"schemes": []}

    def test_capabilities_opt_in_serialises(self) -> None:
        profile = generate()
        card = build_agent_card(
            profile,
            name="Olive",
            capabilities=A2ACapabilities(streaming=True, push_notifications=True),
        )
        parsed = json.loads(card_canonical_bytes(card).decode("utf-8"))
        assert parsed["capabilities"]["streaming"] is True
        assert parsed["capabilities"]["pushNotifications"] is True

    def test_authentication_schemes_round_trip(self) -> None:
        profile = generate()
        card = build_agent_card(
            profile,
            name="Pete",
            authentication=A2AAuthentication(schemes=["bearer", "rfc9421"]),
        )
        parsed = json.loads(card_canonical_bytes(card).decode("utf-8"))
        assert parsed["authentication"]["schemes"] == ["bearer", "rfc9421"]


class TestSignVerifyAgentCard:
    def test_sign_then_verify_roundtrip(self) -> None:
        profile = generate()
        assert profile.private_key is not None
        card = build_agent_card(profile, name="Grace")
        bytes_ = card_canonical_bytes(card)
        sig = sign_agent_card(bytes_, profile.private_key)

        assert verify_agent_card(bytes_, sig, profile.public_key) is True

    def test_verify_rejects_modified_bytes(self) -> None:
        profile = generate()
        assert profile.private_key is not None
        card = build_agent_card(profile, name="Hank")
        bytes_ = card_canonical_bytes(card)
        sig = sign_agent_card(bytes_, profile.private_key)

        tampered = bytes_ + b" "
        assert verify_agent_card(tampered, sig, profile.public_key) is False

    def test_verify_rejects_wrong_public_key(self) -> None:
        profile = generate()
        other = generate()
        assert profile.private_key is not None
        card = build_agent_card(profile, name="Iris")
        bytes_ = card_canonical_bytes(card)
        sig = sign_agent_card(bytes_, profile.private_key)

        assert verify_agent_card(bytes_, sig, other.public_key) is False

    def test_sign_rejects_wrong_length_private_key(self) -> None:
        profile = generate()
        card = build_agent_card(profile, name="Jane")
        bytes_ = card_canonical_bytes(card)

        with pytest.raises(ValueError, match="must be 32 bytes"):
            sign_agent_card(bytes_, b"\x00" * 16)

    def test_verify_returns_false_on_short_public_key(self) -> None:
        profile = generate()
        assert profile.private_key is not None
        card = build_agent_card(profile, name="Kara")
        bytes_ = card_canonical_bytes(card)
        sig = sign_agent_card(bytes_, profile.private_key)

        assert verify_agent_card(bytes_, sig, b"\x00" * 16) is False

    def test_verify_returns_false_on_garbage_signature(self) -> None:
        profile = generate()
        card = build_agent_card(profile, name="Liam")
        bytes_ = card_canonical_bytes(card)

        assert verify_agent_card(bytes_, b"\x00" * 64, profile.public_key) is False
